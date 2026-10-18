---
title: "Implant Fileless: La Composicion de Primitivas como Arma"
date: 2026-10-16
description: "Analisis de como la composicion de primitivas del kernel Linux (mprotect, memfd_create, ptrace) produce capacidades ofensivas emergentes."
tags: ["linux", "syscalls", "implant", "fileless", "ptrace", "composition", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

**Prerequisitos:** [mprotect como Vector de Ataque](/research/mprotect-ejecucion-dinamica-de-codigo-en-linux/) · [memfd_create y Fileless Execution](/research/memfd-create-ejecucion-sin-archivo-en-linux/) · [ptrace e Inyeccion de Procesos](/research/ptrace-inyeccion-de-procesos-en-linux/)

---

## Resumen

Las tres investigaciones anteriores en esta serie documentaron primitivas individuales: `mprotect` para ejecutar codigo dinamicamente, `memfd_create` para eliminar la presencia en disco, y `ptrace` para inyectar en procesos ajenos. Cada una demostro una capacidad aislada con alcance limitado. Esta investigacion documenta lo que sucede cuando esas primitivas dejan de ser ejercicios independientes y se componen en una unica herramienta: un implant fileless con capacidad de migracion. El resultado no es la suma de las partes — es un salto cualitativo en capacidad que solo es posible cuando se entiende cada primitiva lo suficiente como para integrarlas.

---

## 1. El Argumento de la Composicion

Existe una diferencia fundamental entre conocer tecnicas individuales y saber componerlas.

Quien entiende `memfd_create` puede ejecutar un binario sin disco. Quien entiende `ptrace` puede inyectar en otro proceso. Pero quien entiende ambas puede ejecutar un binario sin disco *dentro de un proceso que no es el suyo*. La combinacion produce una capacidad que ninguna de las dos ofrece por separado.

Este principio — que la composicion de primitivas genera capacidades emergentes — es central en la seguridad ofensiva. Los frameworks como Metasploit y Cobalt Strike lo aplican internamente: combinan carga en memoria, inyeccion de procesos, comunicacion encubierta, y persistencia en flujos integrados. La diferencia es que esos frameworks abstraen la composicion. Sus usuarios seleccionan opciones de un menu. La maquinaria interna coordina las primitivas.

La pregunta que motiva esta investigacion no es "como uso estas tecnicas" sino **"que emerge cuando se combinan, y por que esa combinacion es mas que la suma de sus partes"**.

---

## 2. Anatomia del Implant

### 2.1 La Cadena de Ejecucion

El sistema opera como una secuencia de tres etapas, cada una construida sobre la anterior:

**Etapa 1 — Carga sin disco.** Un loader contiene el binario del implant embebido en su propia seccion de datos. Al ejecutarse, crea un file descriptor anonimo en memoria mediante `memfd_create`, escribe el binario del implant en ese descriptor, y lo ejecuta a traves de la ruta virtual `/proc/self/fd/N`. El proceso del loader se reemplaza completamente por el implant. Despues de esta transicion, el loader deja de existir y el implant esta corriendo en memoria sin que ningun archivo en el filesystem lo respalde.

**Etapa 2 — Operacion.** El implant establece una conexion TCP reversa usando syscalls de socket directas. Entra en un ciclo de recepcion de comandos y despacho de operaciones. Cada operacion — desde reportar informacion del sistema hasta ejecutar comandos o inspeccionar el mapa de memoria — se implementa exclusivamente con syscalls, sin invocar funciones de libc en ningun momento.

**Etapa 3 — Migracion.** Cuando se decide mover la ejecucion a otro proceso, el implant usa `ptrace` para inyectar un shellcode de conexion reversa en el proceso objetivo. El shellcode crea su propia conexion de red, redirige los descriptores estandar del proceso al socket, y reemplaza la imagen del proceso con un shell interactivo. El proceso original del implant puede seguir operando o terminar — la presencia persiste en el nuevo proceso.

Cada etapa depende de la anterior: la carga sin disco posibilita que el implant no tenga presencia en el filesystem, la operacion via syscalls directas evita los hooks de userspace, y la migracion permite que la ejecucion sobreviva la terminacion del proceso original.

### 2.2 La Ausencia de libc como Decision de Diseno

La decision de no usar libc tiene consecuencias operacionales concretas.

Cuando un programa llama a `connect()` a traves de libc, la llamada pasa por la Procedure Linkage Table (PLT), que resuelve el simbolo en la libreria compartida. Un defensor que hookee la PLT o use `LD_PRELOAD` para interponer su propia version de `connect()` intercepta la llamada. `ltrace` registra cada invocacion a funciones de libreria. Un EDR que monitoree las llamadas a libc ve toda la actividad de red del proceso.

Cuando el mismo programa invoca la syscall `connect` directamente (numero 42 en x86_64, argumentos en registros, instruccion `syscall`), ninguno de esos mecanismos lo detecta. No hay PLT que hookear porque no hay resolucion de simbolos. No hay libreria compartida que interponer porque no se usa ninguna. `ltrace` no reporta nada porque no hay llamadas a librerias. La operacion es invisible para toda herramienta que opere a nivel de userspace.

La unica capa que ve la operacion es el kernel mismo: `strace` (que usa ptrace internamente), auditd, y eBPF. Estas son herramientas de un nivel de sofisticacion significativamente mayor que las defensas de userspace, y no todas las organizaciones las tienen configuradas para monitoreo activo.

### 2.3 Comandos como Primitivas

Cada comando del implant es una decision sobre el tradeoff entre visibilidad y flexibilidad.

Los comandos que el implant implementa nativamente — informacion del sistema, lectura de mapas de memoria, listado de directorios — operan dentro del proceso del implant sin crear procesos hijos. Desde la perspectiva de un monitor de procesos, no sucede nada observable: un proceso lee su propio `/proc/self/maps` o invoca `getdents64` sobre un directorio. Son operaciones que cualquier proceso realiza como parte de su funcionamiento normal.

La ejecucion de comandos arbitrarios requiere un tradeoff diferente. Para ejecutar un programa externo, el implant necesita crear un proceso hijo (`fork`), redirigir su salida a un pipe, ejecutar el programa (`execve`), capturar el output, y enviarlo. Cada uno de estos pasos es observable: `fork` crea un proceso nuevo visible en `ps`, `execve` carga un binario que puede ser inspeccionado, la cadena de padre-hijo es visible en el arbol de procesos.

Un implant bien disenado minimiza la necesidad de ejecucion externa implementando la mayor cantidad posible de funcionalidad de forma nativa. Cada comando nativo es una operacion invisible. Cada ejecucion externa es una operacion observable. El balance entre ambos define el perfil de deteccion del implant.

---

## 3. La Migracion como Capacidad Emergente

### 3.1 Por que Migrar

La migracion existe porque todo proceso tiene un ciclo de vida limitado.

El proceso que ejecuta el implant puede ser terminado por un administrador, cerrado por un timeout del sistema, o identificado como anomalo por un EDR. Si la unica instancia de ejecucion del implant reside en ese proceso, la terminacion implica perdida total de acceso.

La migracion resuelve este problema de la forma mas directa posible: mueve la ejecucion a un proceso que tiene menor probabilidad de ser terminado. Un servicio del sistema como `sshd`, `cron`, o un servidor web es un candidato ideal: son procesos longevos, esperados en el sistema, y cuya actividad de red (en el caso de servicios de red) enmascara las comunicaciones del payload.

### 3.2 La Mecanica de la Composicion

La migracion es donde la composicion de primitivas se manifiesta de forma mas clara.

Para migrar, el implant necesita:

1. **Conocimiento del target.** Se selecciona un proceso destino. El implant puede asistir en esta seleccion mostrando el arbol de procesos o los mapas de memoria de procesos candidatos — capacidades implementadas usando las mismas syscalls de lectura de `/proc` documentadas en esta serie.

2. **Control del proceso remoto.** El implant usa `ptrace` para attacharse al proceso destino, detener su ejecucion, leer sus registros y memoria, escribir el payload, y reanudar la ejecucion.

3. **Establecimiento de comunicacion independiente.** El payload inyectado no puede depender de la conexion del implant original — esa conexion pertenece al proceso original y no es transferible. El payload necesita establecer su propia conexion de red. Esto significa que el shellcode inyectado debe contener la logica completa de `socket` + `connect` + redireccion de descriptores, implementada en codigo maquina position-independent.

4. **Reemplazo del proceso.** Una vez que el payload tiene su propia conexion, ejecuta `execve` para reemplazar la imagen del proceso destino. El resultado es un shell interactivo corriendo dentro de un proceso que, desde la perspectiva del listado de procesos, no cambio: mismo PID, mismo PPID, mismo usuario. Solo su contenido es diferente.

### 3.3 La Cuestion del Reinicio de Syscalls

Un detalle tecnico que no emerge hasta que se intenta la composicion real: cuando un proceso esta en medio de una syscall bloqueante (como `nanosleep` en un proceso `sleep`), el kernel registra el numero de syscall en un campo especial de la estructura de registros (`orig_rax`). Si el proceso es interrumpido y luego reanudado, el kernel puede intentar reiniciar la syscall original en vez de ejecutar desde el nuevo instruction pointer.

Este comportamiento es correcto para el caso de uso previsto (debugging): si un debugger detiene un proceso durante un `read()` y lo reanuda, el usuario espera que el `read()` continue. Pero para inyeccion, es un problema: se quiere que la ejecucion salte al shellcode, no que vuelva al `nanosleep` interrumpido.

La solucion es invalidar el campo `orig_rax` escribiendo un valor negativo antes de reanudar el proceso. Esto le indica al kernel que no hay syscall pendiente que reiniciar.

Este es un ejemplo de conocimiento que solo se adquiere en la practica de la composicion. Ninguna de las investigaciones individuales necesito considerar la interaccion entre la interrupcion de syscalls y la inyeccion de codigo. Solo cuando ambas operaciones se combinan en un flujo real — interrumpir un proceso bloqueado para inyectar shellcode — el problema se manifiesta.

---

## 4. Perspectiva Ofensiva: La Suma de Evasiones

### Capas de Invisibilidad

Cada primitiva contribuye una capa de evasion. Compuestas, las capas se multiplican:

**Sin presencia en disco.** El implant fue cargado via `memfd_create`. No existe como archivo en ningun filesystem. Los scanners de archivos (antivirus basado en firmas, file integrity monitoring) no tienen nada que escanear. El unico indicador estatico es `/proc/<pid>/exe` apuntando a `memfd:nombre (deleted)`.

**Sin hooks de libc.** Toda operacion usa syscalls directas. `LD_PRELOAD`, interposicion de librerias, y `ltrace` son ciegos a la actividad del implant. Un nivel completo de instrumentacion defensiva queda neutralizado.

**Sin proceso nuevo despues de migracion.** Despues de migrar, la ejecucion reside en un proceso preexistente. No hay nuevo binario, no hay nueva linea de comandos, no hay nuevo PID. El proceso victima retiene su identidad externa mientras ejecuta codigo inyectado.

**Operaciones nativas silenciosas.** Los comandos implementados via syscalls directas (lectura de directorios, inspeccion de memoria, informacion del sistema) no generan procesos hijos ni invocaciones a programas externos. Son indistinguibles de las operaciones normales de cualquier proceso.

Ninguna de estas capas es absoluta. Cada una tiene indicadores detectables. Pero un defensor que quiera detectar el implant necesita cubrir *todas* las capas: monitorear `/proc/*/exe` para fileless execution, instrumentar syscalls via eBPF para actividad sin libc, auditar `ptrace` para inyeccion, y analizar comportamiento para operaciones anomalas. La omision de cualquier capa deja un punto ciego.

### Lo que un Framework Abstrae

Cuando un framework como Metasploit ejecuta una migracion de meterpreter entre procesos, internamente ejecuta exactamente estas primitivas. La diferencia es el nivel de abstraccion: se selecciona `migrate <pid>` y el framework coordina el attach, la inyeccion, y la ejecucion.

Implementar la misma capacidad desde las primitivas crudas revela los puntos de decision que la abstraccion oculta:

- ¿En que direccion de memoria se inyecta? El framework elige automaticamente. Sin abstraccion, hay que entender por que se usa la direccion actual de RIP (porque esa memoria ya es ejecutable).
- ¿Como se maneja la escritura parcial de words? POKETEXT escribe 8 bytes a la vez. Si el shellcode no es multiplo de 8, la ultima escritura necesita una operacion de merge con los bytes originales.
- ¿Que pasa si el target esta en una syscall bloqueante? Hay que descubrir el problema de `orig_rax` y la politica de reinicio de syscalls del kernel.

Cada una de estas decisiones es invisible para el usuario del framework y obligatoria para quien implementa la herramienta.

---

## 5. Perspectiva Defensiva: Detectar la Composicion

### 5.1 Indicadores por Capa

| Capa | Indicador | Donde Buscarlo | Confiabilidad |
|---|---|---|---|
| Fileless | `/proc/<pid>/exe` → `memfd:*` | Escaneo periodico de `/proc/*/exe` | Alta |
| Sin libc | Proceso sin `libc.so` en `/proc/<pid>/maps` pero con actividad de red | Correlacion maps vs conexiones | Media-alta |
| Migracion | `ptrace ATTACH` desde proceso no-debugger | auditd, eBPF en syscall 101 | Alta |
| Shellcode | Transicion de RIP a region inesperada post-ptrace | Monitoreo de registros pre/post detach | Baja (requiere instrumentacion profunda) |
| Conexion C2 | Conexion TCP saliente a IP/puerto inusual | `ss -tnp`, logs de firewall | Media |
| Ejecucion | `fork`+`execve` desde proceso que normalmente no ejecuta | Baseline comportamental | Media |

### 5.2 La Deteccion por Correlacion

Los indicadores individuales generan falsos positivos. Un proceso sin libc en maps no es necesariamente malicioso (binarios estaticos existen). Una invocacion de ptrace no es necesariamente inyeccion (debuggers existen). Una conexion TCP saliente no es necesariamente C2 (aplicaciones legitimas hacen conexiones).

La deteccion efectiva del implant compuesto requiere **correlacion temporal y contextual** de multiples indicadores:

- Un proceso cuyo `/proc/<pid>/exe` apunta a un memfd **Y** tiene una conexion TCP saliente **Y** no tiene libc en su mapa de memoria → alta probabilidad de implant fileless.
- Un servicio del sistema que recibe un `ptrace ATTACH` **Y** poco despues establece una nueva conexion TCP que no existia antes → alta probabilidad de migracion post-inyeccion.
- Un proceso que ejecuta `fork`+`execve` de `/bin/sh` **Y** cuyos descriptores stdin/stdout apuntan a un socket **Y** ese socket se creo recientemente → alta probabilidad de reverse shell.

Ningun indicador individual justifica una alerta de alta prioridad. La combinacion de dos o mas, en una ventana temporal estrecha, si la justifica. Los sistemas de deteccion que correlacionan multiples fuentes de telemetria (SIEM con reglas de correlacion, EDR con deteccion comportamental) estan disenados para exactamente este tipo de patron.

### 5.3 El Punto Ciego Temporal

La ventana de deteccion para la migracion es particularmente estrecha. La secuencia completa — attach, inyeccion, ejecucion, detach — puede completarse en milisegundos. Un sistema que muestrea `/proc/<pid>/status` cada segundo tiene una probabilidad baja de capturar el campo `TracerPid` durante la ventana de inyeccion.

Despues de la migracion, el proceso victima ha sido reemplazado por un shell. Su `/proc/<pid>/exe` ahora apunta a `/bin/sh` (o `/bin/dash`), lo cual es el indicador mas persistente. Pero un proceso ejecutando `/bin/sh` no es inherentemente sospechoso — scripts de sistema, cron jobs, y sesiones interactivas usan shells constantemente.

La deteccion mas robusta no busca el evento de inyeccion (demasiado breve) sino sus **consecuencias**: un proceso que cambio de binario (`exe` apunta a algo diferente de lo que el proceso fue originalmente), un servicio que ahora tiene conexiones de red que no tenia antes, o un cambio en el patron de syscalls de un proceso longevo.

### 5.4 Mitigaciones Estructurales

**seccomp-bpf:** Restringir `memfd_create`, `ptrace`, y `execveat` para procesos que no los necesitan. La mayoria de los servicios de produccion nunca usan estas syscalls, asi que el impacto operacional es minimo. Los contenedores modernos ya eliminan `SYS_PTRACE` por defecto.

**Yama ptrace_scope:** Scope 2 o 3 bloquea ptrace para usuarios no privilegiados. Esto impide la migracion a menos que se tenga `CAP_SYS_PTRACE` o root.

**Namespaces y cgroups:** El aislamiento de procesos en namespaces de PID y red limita el alcance de la migracion. Un implant dentro de un contenedor no puede migrar a procesos fuera del contenedor (sin escape de contenedor adicional).

**Monitoreo de integridad de procesos:** Verificar periodicamente que `/proc/<pid>/exe` de servicios criticos apunta al binario esperado. Cualquier cambio inesperado merece investigacion inmediata.

**Segmentacion de red:** Detectar y alertar sobre conexiones salientes desde servicios que no deberian iniciar conexiones. Un `sshd` que de pronto establece una conexion TCP a un puerto alto en una IP externa es altamente sospechoso.

---

## 6. Reflexion Final

Esta investigacion completa un arco que comenzo con la pregunta mas basica — "como le pido al kernel que haga algo" — y culmina con un sistema que compone multiples respuestas en una herramienta cohesiva.

Cada primitiva individual es una capacidad del kernel disenada para un proposito legitimo. `memfd_create` existe para memoria compartida segura. `ptrace` existe para debugging. Las syscalls de socket existen para comunicacion de red. `fork` y `execve` existen para crear y ejecutar procesos.

La leccion central no ha cambiado desde la primera investigacion: **el sistema funciona exactamente como fue especificado**. No hay bugs explotados, no hay vulnerabilidades aprovechadas, no hay comportamiento inesperado del kernel. Lo que hay es una composicion de interfaces publicas que produce un efecto que los disenadores no contemplaron como caso de uso principal.

La defensa contra esta composicion no puede basarse en bloquear primitivas individuales — hacerlo romperia funcionalidad legitima que depende de ellas. Tiene que basarse en detectar los patrones de composicion: la correlacion temporal de operaciones que individualmente son benignas pero que combinadas indican actividad adversarial.

Este es el problema irreducible de la seguridad de sistemas: un kernel que expone primitivas lo suficientemente poderosas como para construir herramientas utiles es, por definicion, un kernel que expone primitivas lo suficientemente poderosas como para construir herramientas ofensivas. La linea entre ambas no esta en las primitivas — esta en la intencion y el contexto de quien las compone.

---

*Investigacion realizada como parte del proyecto [Black Hat Zig](https://github.com/JorgeBeritan) — documentacion de tecnicas ofensivas a nivel de syscall en Linux.*
