---
title: "Inyeccion de Procesos en Linux: ptrace como Herramienta de Control Total"
date: 2026-10-12
description: "Uso de la syscall ptrace para leer, escribir y ejecutar codigo en el contexto de un proceso ajeno en Linux."
tags: ["linux", "syscalls", "ptrace", "process-injection", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

**Prerequisitos:** [mprotect como Vector de Ataque](/research/mprotect-ejecucion-dinamica-de-codigo-en-linux/) · [memfd_create y Fileless Execution](/research/memfd-create-ejecucion-sin-archivo-en-linux/)

---

## Resumen

Las tecnicas documentadas anteriormente en esta serie — ejecucion dinamica de shellcode via `mprotect` y ejecucion sin archivo via `memfd_create` — operan dentro del espacio de memoria del propio proceso. Esta investigacion cruza esa frontera: documenta el uso de la syscall `ptrace` para leer, escribir y ejecutar codigo en el contexto de un proceso ajeno. Es la convergencia de todas las primitivas estudiadas hasta ahora y representa la capacidad ofensiva mas completa que ofrece el kernel Linux desde userspace.

---

## 1. El Salto Conceptual

Existe una diferencia cualitativa entre ejecutar codigo en tu propio proceso y ejecutar codigo en el proceso de otro.

En las tecnicas anteriores, se crea memoria, se escribe el payload, y se ejecuta. El proceso que realiza la ejecucion es el mismo que fue creado. Un defensor que lista los procesos activos veria un proceso desconocido — un binario que no deberia estar ahi.

La inyeccion de procesos elimina esa visibilidad. El payload se ejecuta dentro de un proceso **que ya existia antes de la operacion**: un servidor web, un demonio del sistema, un proceso del usuario. Desde la perspectiva de un listado de procesos, nada cambio. No hay proceso nuevo, no hay binario desconocido, no hay linea de comandos sospechosa.

La pregunta que esta tecnica responde no es "como ejecuto mi codigo" sino **"como hago que un proceso legitimo ejecute codigo arbitrario sin que nadie note la diferencia"**.

---

## 2. La Primitiva: ptrace

### Que es y por que existe

`ptrace` (process trace) es una syscall que permite a un proceso — el **tracer** — observar y controlar la ejecucion de otro proceso — el **tracee**. Es la base sobre la que se construyen todos los debuggers en Linux: GDB, LLDB, strace, ltrace. Sin `ptrace`, el debugging interactivo de procesos en Linux no seria posible.

La syscall ofrece un conjunto de operaciones:

| Operacion | Que permite |
|---|---|
| ATTACH | Conectarse a un proceso existente y detener su ejecucion |
| GETREGS | Leer todos los registros del procesador del tracee |
| SETREGS | Escribir los registros del procesador del tracee |
| PEEKTEXT | Leer una word (8 bytes) de la memoria del tracee |
| POKETEXT | Escribir una word (8 bytes) en la memoria del tracee |
| CONT | Reanudar la ejecucion del tracee |
| DETACH | Desconectarse del tracee y dejarlo continuar |

Cada una de estas operaciones fue disenada para debugging. GETREGS permite a GDB mostrar el estado del procesador. PEEKTEXT permite inspeccionar memoria. POKETEXT permite insertar breakpoints. CONT permite ejecutar instruccion por instruccion.

El punto critico es que **la interfaz no distingue entre uso para debugging y uso para inyeccion**. Las mismas operaciones que permiten a GDB insertar un breakpoint (POKETEXT con el byte 0xCC) permiten a un atacante escribir shellcode arbitrario.

### Comparacion con Windows

En Windows, las capacidades equivalentes estan distribuidas en multiples APIs:

- `OpenProcess` → obtener un handle al proceso
- `ReadProcessMemory` / `WriteProcessMemory` → leer/escribir memoria
- `GetThreadContext` / `SetThreadContext` → leer/escribir registros
- `CreateRemoteThread` / `NtCreateThreadEx` → crear un hilo en el proceso remoto
- `VirtualAllocEx` / `VirtualProtectEx` → gestionar memoria remota

Son al menos seis APIs coordinadas para lograr lo que `ptrace` hace con una sola syscall y diferentes codigos de operacion. La superficie de monitoreo en Windows es mas amplia precisamente porque hay mas puntos de intercepcion. En Linux, todo pasa por un unico punto: la syscall 101.

Esto tiene implicaciones defensivas directas. En Windows, un EDR puede hookear `CreateRemoteThread` especificamente para detectar inyeccion sin afectar el debugging. En Linux, monitorear `ptrace` para detectar inyeccion inevitablemente detecta (y potencialmente interfiere con) el debugging legitimo.

---

## 3. El Flujo de Inyeccion

### Fase 1 — Seleccion del target

Antes de inyectar, hay que elegir un proceso target. La seleccion depende del objetivo:

- **Persistencia**: un demonio que siempre esta corriendo (sshd, cron, un servicio web).
- **Evasion**: un proceso que naturalmente genera trafico de red (un browser, un cliente DNS) para camuflar comunicaciones C2.
- **Escalacion**: un proceso que corre con privilegios superiores.

El proceso ideal es uno que sea comun, longevo, y cuya actividad normal enmascare la actividad del payload.

### Fase 2 — Attach y detencion

Se invoca `ptrace(ATTACH, pid)`. El kernel envia una senal SIGSTOP al tracee, deteniendo su ejecucion. Se usa `waitpid` para confirmar que el tracee se detuvo.

Este es el momento mas visible de la operacion. El proceso victima se congela brevemente. Si el proceso esta manejando conexiones activas o timers criticos, la pausa puede causar efectos observables (timeouts, conexiones cortadas).

### Fase 3 — Reconocimiento del estado

Se leen los registros del tracee con GETREGS. El registro mas importante es **RIP** (instruction pointer): indica exactamente donde estaba ejecutando el proceso cuando fue detenido. Tambien se captura **RSP** (stack pointer) y el resto de registros de proposito general.

Este estado completo se guarda. Es la "fotografia" del proceso antes de la inyeccion, y sera necesaria para la restauracion posterior.

### Fase 4 — Preservacion de memoria

Antes de escribir el shellcode, se leen y guardan los bytes originales en la direccion donde se va a inyectar (tipicamente la direccion actual de RIP). Sin estos bytes guardados, el proceso no puede ser restaurado a su estado original.

La lectura se hace con PEEKTEXT, que retorna una word (8 bytes) por invocacion. Para un shellcode de N bytes, se necesitan ceil(N/8) invocaciones.

### Fase 5 — Escritura del payload

Se escribe el shellcode en la memoria del tracee usando POKETEXT, que escribe una word por invocacion. El shellcode sobreescribe las instrucciones originales en la direccion de RIP.

Una sutileza tecnica: POKETEXT escribe words completas de 8 bytes. Si el shellcode no es multiplo de 8, la ultima escritura necesita ser una operacion de "merge": leer la word original con PEEKTEXT, reemplazar solo los bytes necesarios, y escribir la word combinada con POKETEXT. Sin este cuidado, se corrompen bytes adyacentes al shellcode.

### Fase 6 — Ejecucion

Se invoca `ptrace(CONT, pid)`. El tracee reanuda su ejecucion, pero ahora RIP apunta al shellcode inyectado. El procesador decodifica y ejecuta el shellcode como si fueran las instrucciones originales del proceso.

El shellcode termina con una instruccion `int3` (byte 0xCC). Esta instruccion genera una excepcion de breakpoint (SIGTRAP) que detiene el tracee y notifica al tracer. Es el mecanismo de retorno: el shellcode senaliza "termine" sin necesidad de conocer una direccion de retorno.

Un punto de diseno importante: en la ejecucion via `mprotect` documentada anteriormente, el shellcode usaba `ret` para volver al caller. Eso era posible porque habia un `call` previo que deposito una direccion de retorno en el stack. En la inyeccion via `ptrace`, no hay `call` — el RIP fue modificado directamente. No hay direccion de retorno en el stack. El `int3` resuelve este problema: detiene la ejecucion y devuelve el control al tracer a traves del mecanismo de senales del kernel, no a traves del stack.

### Fase 7 — Restauracion

Despues de que el shellcode ejecuta y el tracee se detiene en `int3`, el tracer:

1. Restaura los bytes originales en memoria (POKETEXT con los bytes guardados en la Fase 4).
2. Restaura los registros originales (SETREGS con los valores guardados en la Fase 3).

El proceso victima queda en el estado exacto en que estaba antes de la inyeccion. Su memoria contiene las instrucciones originales, sus registros apuntan donde apuntaban, y su stack no fue modificado.

### Fase 8 — Detach

Se invoca `ptrace(DETACH, pid)`. La relacion de tracing se disuelve. El tracee continua su ejecucion normal desde el punto exacto donde fue detenido.

Si la operacion fue realizada correctamente, el proceso victima no tiene forma de saber que fue inyectado. Su ejecucion continua sin errores, sin crashes, sin inconsistencias en su estado interno.

---

## 4. La Cuestion del Stealth

### Que evidencia queda

**Durante la inyeccion:**
- El proceso victima tiene el estado `t` (traced) en `/proc/<pid>/status`. Cualquier herramienta que consulte este campo ve que el proceso esta siendo traceado.
- El campo `TracerPid` en `/proc/<pid>/status` muestra el PID del tracer.
- La pausa en la ejecucion del tracee puede ser observable si maneja conexiones activas.

**Despues del detach:**
- `TracerPid` vuelve a 0.
- El estado del proceso vuelve a su estado normal.
- La memoria y los registros fueron restaurados.
- **No queda evidencia persistente en el proceso.** Sin un monitoreo activo durante la ventana de inyeccion, no hay artefacto que un analisis posterior pueda encontrar.

### La ventana temporal

La ventana de deteccion es el tiempo entre ATTACH y DETACH. Para un shellcode pequeno, este tiempo puede ser de microsegundos. Un defensor que no este muestreando activamente `/proc/<pid>/status` en ese intervalo preciso no detectara la inyeccion.

Esto crea una asimetria fundamental: el atacante controla la duracion de la ventana, y el defensor necesita estar observando durante esa ventana especifica. El atacante necesita tener exito una vez; el defensor necesita estar vigilando todo el tiempo.

---

## 5. Cadena de Ataque Completa

Esta tecnica no existe en aislamiento. Representa la culminacion de las primitivas documentadas en esta serie, y su poder real emerge cuando se encadenan:

### Reconocimiento: /proc/self/maps

Antes de inyectar, se lee `/proc/<pid>/maps` del proceso victima para entender su layout de memoria. Se identifican regiones ejecutables (donde RIP podria estar), regiones escribibles (alternativas para depositar el payload), y la presencia de librerias especificas (para resolver funciones dinamicamente).

### Ejecucion dinamica: mprotect

Si se necesita inyectar un payload mas grande que el espacio disponible en la region actual de RIP, se puede usar `ptrace` para invocar `mmap` en el contexto de la victima (escribiendo un shellcode corto que llama a `mmap`, ejecutandolo, y luego escribiendo el payload real en la nueva region). Despues se usa `mprotect` para hacer esa region ejecutable.

### Fileless delivery: memfd_create

El payload final puede ser un ELF completo cargado via `memfd_create` dentro del proceso victima. Se inyecta un loader minimo que crea un memfd, escribe el ELF, y lo ejecuta con `execveat` o lo mapea en memoria. El binario del payload nunca toca disco.

### La cadena completa

1. Leer `/proc/<pid>/maps` → reconocimiento del layout de memoria
2. `ptrace ATTACH` → tomar control del proceso
3. Inyectar un stub que llame a `mmap` → crear espacio para el payload
4. `mprotect` la nueva region → hacerla ejecutable
5. Escribir el payload real (o un loader de `memfd_create`) → depositar el codigo
6. Modificar RIP → ejecutar el payload
7. Restaurar y DETACH → no dejar rastro

Cada tecnica individualmente tiene un alcance limitado. Encadenadas, representan la capacidad de ejecutar un programa arbitrario dentro de un proceso legitimo sin que exista ningun archivo en disco ni ningun proceso nuevo visible.

---

## 6. Perspectiva Defensiva

### Deteccion en tiempo real

**Monitoreo de ptrace via auditd/eBPF:**
La senal mas directa es la invocacion de `ptrace(ATTACH)` desde un proceso que no es un debugger conocido. Una regla de auditd que registre la syscall 101 con el argumento ATTACH (16) captura cada intento de inyeccion. El desafio es distinguir attach de debugging legitimo de attach malicioso — el contexto del proceso que invoca la syscall es la clave.

**Escaneo periodico de TracerPid:**
Un agente de seguridad que lea `/proc/<pid>/status` periodicamente puede detectar procesos siendo traceados. Si un servicio critico (sshd, nginx, un proceso de base de datos) tiene TracerPid distinto de cero y no hay una sesion de debugging conocida, la alerta es de alta prioridad.

**Monitoreo de estado de procesos:**
El estado `t` (traced/stopped) en `/proc/<pid>/stat` indica tracing activo. Un proceso que transiciona a estado `t` sin que el administrador haya iniciado un debugger merece investigacion.

### Prevencion

**Yama LSM (ptrace_scope):**
El modulo Yama del kernel implementa restricciones sobre quien puede usar ptrace:

- **Scope 0:** Sin restricciones. Cualquier proceso puede tracear cualquier otro del mismo UID.
- **Scope 1:** Solo procesos descendientes directos. Un proceso solo puede tracear sus hijos.
- **Scope 2:** Solo administradores con CAP_SYS_PTRACE.
- **Scope 3:** ptrace completamente deshabilitado.

La mayoria de las distribuciones orientadas a servidores usan scope 1 por defecto. Scope 2 o 3 bloquea la tecnica para usuarios no privilegiados, pero tambien impide el debugging normal.

**seccomp-bpf:**
Un filtro seccomp puede bloquear `ptrace` completamente para procesos que no la necesitan. Los contenedores modernos (Docker, Kubernetes) ya aplican esto por defecto: el capability `SYS_PTRACE` se elimina del conjunto de capacidades del contenedor.

**Namespaces de PID:**
Si la victima potencial corre en un namespace de PID diferente al del atacante, `ptrace` no puede alcanzarla. El aislamiento de namespaces es una barrera efectiva contra la inyeccion entre contextos de ejecucion.

**SELinux/AppArmor:**
Ambos frameworks pueden definir politicas que restringen que procesos pueden ser traceados y por quien. Una politica bien configurada puede permitir que GDB tracee procesos del usuario pero denegar tracing entre servicios del sistema.

### La limitacion del enfoque defensivo

El desafio fundamental es que `ptrace` es una herramienta critica del ecosistema. Los debuggers la necesitan. Los tracers de rendimiento la necesitan. Algunas herramientas de sandboxing la necesitan. Bloquearla completamente rompe flujos de trabajo de desarrollo y operaciones.

La defensa efectiva no puede ser un interruptor binario (permitir/bloquear). Tiene que ser contextual: ¿quien esta invocando ptrace? ¿sobre que proceso? ¿en que circunstancia? Las respuestas a estas preguntas requieren politicas granulares y monitoreo activo, no reglas estaticas.

---

## 7. Reflexion Final

`ptrace` completa un arco que comenzo con la escritura de bytes en memoria propia y culmina con el control total de procesos ajenos. Cada paso en esta progresion — `mprotect`, `memfd_create`, `ptrace` — agrego una capacidad nueva, y cada capacidad fue proporcionada por el kernel a traves de interfaces publicas, documentadas, y disenadas para uso legitimo.

La seguridad de un sistema no se puede evaluar mirando cada componente en aislamiento. `ptrace` es seguro en el contexto de debugging. `memfd_create` es seguro en el contexto de memoria compartida. `mprotect` es seguro en el contexto de compilacion JIT. Es la **composicion** de estas primitivas con intencion adversarial lo que genera la capacidad ofensiva.

Un atacante no descubre vulnerabilidades en estas syscalls. Descubre que, combinadas de cierta manera, producen un efecto que los disenadores no anticiparon como caso de uso principal. El sistema funciona exactamente como fue especificado. La especificacion simplemente no contemplo todos los usos posibles.

---

*Investigacion realizada como parte del proyecto [Black Hat Zig](https://github.com/JorgeBeritan) — documentacion de tecnicas ofensivas a nivel de syscall en Linux.*
