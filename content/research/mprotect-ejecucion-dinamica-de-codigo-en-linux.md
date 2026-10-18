---
title: "Ejecucion Dinamica de Codigo en Linux: mprotect como Vector de Ataque"
date: 2026-10-08
description: "Como las primitivas de gestion de memoria del kernel Linux pueden reutilizarse para lograr ejecucion arbitraria de codigo en runtime."
tags: ["linux", "syscalls", "mprotect", "memory-management", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

## Resumen

Esta investigacion documenta como las primitivas de gestion de memoria del kernel Linux, disenadas para uso legitimo por compiladores JIT y loaders dinamicos, pueden ser reutilizadas para lograr ejecucion arbitraria de codigo en runtime. La tecnica no explota ninguna vulnerabilidad: opera enteramente dentro de la interfaz publica del sistema operativo. Se analiza el flujo completo, las condiciones necesarias, y las estrategias de deteccion y mitigacion disponibles.

---

## 1. Punto de Partida

El objetivo fundamental de cualquier operacion ofensiva post-explotacion es ejecutar codigo propio en el contexto de un proceso. La pregunta no es "como rompo el sistema" sino **"que me ofrece el sistema que pueda usar para mis fines?"**

Linux expone toda su funcionalidad al userspace a traves de syscalls. Estas son la interfaz contractual entre los programas y el kernel. No son bugs, no son backdoors: son la API documentada y publica del sistema operativo.

La pregunta entonces se transforma: **¿existe una combinacion de syscalls legitimas que me permita escribir bytes arbitrarios en memoria y despues ejecutarlos?**

La respuesta es si.

---

## 2. El Modelo de Memoria de Linux

Cada proceso en Linux opera dentro de su propio espacio de direcciones virtuales. El kernel mantiene un mapa de regiones de memoria, cada una con permisos especificos:

- **Read (R):** El proceso puede leer los bytes de esa region.
- **Write (W):** El proceso puede modificar los bytes.
- **Execute (X):** El procesador puede interpretar los bytes como instrucciones y ejecutarlas.

Estos permisos se aplican a nivel de **pagina** (bloques de 4096 bytes en x86_64). El hardware enforce estos permisos a traves del bit NX (No-Execute) en las tablas de paginacion. Si un programa intenta ejecutar codigo en una pagina sin permiso X, el procesador genera una excepcion y el kernel mata el proceso con SIGSEGV.

Esto es la base de **DEP** (Data Execution Prevention) y lo que la comunidad llama **W^X** (Write XOR Execute): la politica de que una pagina deberia ser escribible O ejecutable, pero nunca ambas al mismo tiempo.

La pregunta ofensiva ahora es mas especifica: **¿puedo cambiar estos permisos despues de que la memoria ya fue asignada?**

---

## 3. Las Primitivas: mmap y mprotect

### mmap: Solicitar Memoria al Kernel

La syscall `mmap` permite a un proceso solicitar regiones de memoria virtual. En su forma mas basica (mapeo anonimo), le dice al kernel: "dame N bytes de memoria con estos permisos". El kernel busca un hueco en el espacio de direcciones del proceso, configura las tablas de paginacion, y retorna la direccion.

Lo critico es que `mmap` acepta un argumento de proteccion que define los permisos iniciales de la region. Un programa puede pedir memoria con permisos de lectura y escritura (RW), lo cual es completamente normal: asi se asigna memoria para datos, buffers, estructuras.

### mprotect: Cambiar Permisos en Runtime

Aqui esta la pieza central. La syscall `mprotect` permite a un proceso **modificar los permisos de una region de memoria ya existente**. Recibe tres argumentos: la direccion base (alineada a pagina), el tamanio, y los nuevos permisos.

Esta syscall existe por razones completamente legitimas:

- **Compiladores JIT** (V8, LuaJIT, .NET CLR): generan codigo maquina en runtime, lo escriben en memoria RW, y despues necesitan hacerlo ejecutable.
- **Loaders dinamicos** (`ld-linux.so`): cargan librerias compartidas y necesitan ajustar permisos de cada segmento ELF.
- **Garbage collectors**: algunos implementan write barriers manipulando permisos de paginas.
- **Debuggers**: necesitan escribir breakpoints en memoria ejecutable.

El kernel no distingue entre un JIT compiler y un atacante. Ambos usan la misma interfaz, con los mismos argumentos, de la misma manera. La syscall no tiene concepto de "intencion".

---

## 4. La Tecnica: Flujo de Ejecucion

El flujo sigue una logica directa una vez que se entienden las primitivas:

### Fase 1 — Reserva de Espacio

Se solicita al kernel una pagina de memoria con permisos de lectura y escritura. Esta operacion es indistinguible de cualquier asignacion de memoria normal: un programa que llama a `malloc` internamente termina haciendo exactamente lo mismo. No hay nada anomalo en esta solicitud.

### Fase 2 — Escritura del Payload

Con la memoria asignada y con permisos de escritura, se copia el payload (codigo maquina x86_64) a la region. Esto es una escritura de bytes en memoria propia del proceso. Desde la perspectiva del kernel, es identico a llenar un buffer con datos de red o copiar el contenido de un archivo.

El payload debe ser **position-independent**: tiene que funcionar correctamente sin importar en que direccion virtual lo carguen. Esto se logra usando direccionamiento relativo al instruction pointer (RIP-relative en x86_64) en lugar de direcciones absolutas. El payload no puede asumir que va a estar en una direccion fija porque `mmap` retorna direcciones elegidas por el kernel, influenciadas por ASLR.

### Fase 3 — Transicion de Permisos

Aqui ocurre el paso critico. Se usa `mprotect` para cambiar los permisos de la region de RW (lectura/escritura) a RX (lectura/ejecucion). Despues de esta llamada:

- La escritura ya no es posible (se removio W).
- La ejecucion ahora si es posible (se agrego X).

La politica W^X se respeta en todo momento: nunca existio un instante donde la pagina fuera simultaneamente escribible y ejecutable. Primero fue RW (se podia escribir pero no ejecutar), ahora es RX (se puede ejecutar pero no escribir). El kernel permite esta transicion sin objeciones.

### Fase 4 — Transferencia de Control

El paso final es desviar el flujo de ejecucion a la direccion donde reside el payload. En terminos de bajo nivel, esto es un `call` o `jmp` a la direccion retornada por `mmap`. El procesador comienza a decodificar los bytes en esa direccion como instrucciones, y las ejecuta.

Desde la perspectiva del procesador, no hay diferencia entre ejecutar instrucciones que fueron compiladas hace un anio y almacenadas en disco, o instrucciones que fueron escritas hace un microsegundo. Los bytes son bytes.

### Fase 5 — Limpieza

Despues de la ejecucion, la memoria se libera con `munmap`. La region desaparece del mapa de memoria del proceso. No queda rastro de la asignacion en el estado del proceso una vez finalizada la operacion.

---

## 5. Implicaciones Ofensivas

### Por que esta tecnica es relevante

1. **No toca el disco.** El payload existe solo en memoria virtual. Los mecanismos de deteccion basados en escaneo de archivos (antivirus tradicional, file integrity monitoring) no ven nada porque no hay nada que ver en el filesystem.

2. **No requiere privilegios elevados.** Todas las syscalls involucradas son accesibles para procesos no privilegiados. Un usuario normal puede ejecutar este flujo completo.

3. **Es operacionalmente limpia.** No modifica binarios existentes, no crea archivos temporales, no altera el estado persistente del sistema. Si el proceso termina, la evidencia se evapora con el.

4. **Es la base de tecnicas mas avanzadas.** Este patron RW→RX→Execute es el building block de: reflective loading (cargar DLLs/SOs desde memoria), fileless malware (via `memfd_create`), process hollowing, y cualquier forma de inyeccion que no dependa de archivos en disco.

### Combinacion con otras primitivas

La tecnica se vuelve significativamente mas poderosa cuando se combina con:

- **`memfd_create`:** Crea un file descriptor respaldado solo por memoria. Permite ejecutar un ELF completo sin que exista como archivo en disco. El filesystem no registra nada.
- **`ptrace`:** Permite escribir en la memoria de otro proceso y manipular sus registros. Combinado con mprotect, permite inyectar y ejecutar codigo en procesos ajenos.
- **`process_vm_writev`:** Escritura directa en el espacio de direcciones de otro proceso sin necesidad de ptrace completo.

---

## 6. Perspectiva Defensiva

### Deteccion

La deteccion de esta tecnica requiere operar en capas que el atacante no pueda evadir facilmente:

**Monitoreo de syscalls (auditd / seccomp-bpf / eBPF):**
La senal mas clara es la secuencia `mmap(RW)` seguida de `mprotect(RX)` en el mismo rango de direcciones, dentro de un proceso que normalmente no realiza compilacion JIT. Esta transicion de permisos es la firma de la tecnica. Herramientas basadas en eBPF pueden interceptar estas llamadas en tiempo real y correlacionar los argumentos.

**Inspeccion de `/proc/<pid>/maps`:**
Las regiones de memoria anonimas (sin archivo de respaldo) con permisos de ejecucion son sospechosas. La mayoria de las regiones ejecutables en un proceso normal estan respaldadas por archivos en disco (el binario, libc, etc.). Una region anonima ejecutable merece investigacion.

**Analisis de memoria volatil:**
Si se captura un dump de memoria del proceso mientras el payload esta activo, el contenido de la region ejecutable puede ser extraido y analizado. Esto requiere acceso al proceso antes de que libere la memoria.

### Mitigacion

**SELinux / AppArmor:**
Ambos frameworks de Mandatory Access Control pueden restringir que procesos tienen permitido usar `mprotect` con el flag PROT_EXEC. La politica `execmem` de SELinux deniega especificamente esta capacidad. Esta es probablemente la mitigacion mas efectiva disponible.

**seccomp-bpf:**
Permite instalar filtros a nivel de proceso que bloquean syscalls especificas o combinaciones de argumentos. Un filtro seccomp puede prohibir `mprotect` con PROT_EXEC para procesos que no lo necesitan.

**Kernel hardening (grsecurity/PaX):**
Implementaciones como PaX MPROTECT imponen W^X de forma estricta: una pagina que alguna vez fue escribible no puede volverse ejecutable, punto. Esto elimina la tecnica de raiz, pero rompe compatibilidad con JIT compilers y otros usos legitimos.

**Monitoreo comportamental:**
Mas alla de las reglas estaticas, los sistemas de deteccion modernos (EDR) buscan cadenas de comportamiento: un proceso que hace mmap anonimo, escribe contenido con alta entropia, cambia permisos a ejecutable, y transfiere control, genera una alerta compuesta incluso si cada paso individual es benigno.

### La paradoja defensiva

La dificultad fundamental de defender contra esta tecnica es que cada paso individual es una operacion perfectamente legitima. Asignar memoria es normal. Escribir en ella es normal. Cambiar permisos es normal (los JIT compilers lo hacen miles de veces por segundo). Ejecutar codigo en memoria es, literalmente, lo que hace un procesador.

La deteccion efectiva no puede basarse en bloquear operaciones individuales sin romper funcionalidad legitima. Tiene que basarse en **correlacion de contexto**: quien hace esto, por que, y que patron sigue la secuencia completa.

---

## 7. Reflexion Final

Esta tecnica demuestra un principio fundamental de la seguridad ofensiva: **la superficie de ataque no esta solo en los bugs**. Las interfaces legitimas del sistema, disenadas para flexibilidad y poder, son en si mismas vectores cuando se usan con intencion adversarial.

El kernel Linux expone `mprotect` porque los programas lo necesitan. No puede removerlo sin romper una porcion significativa del software que depende de el. Y no puede distinguir automaticamente entre un uso "bueno" y uno "malo" porque la distincion no existe a nivel de syscall: existe solo en la intencion del que invoca la llamada.

Esta tension entre funcionalidad y seguridad no tiene solucion limpia. Las mitigaciones efectivas (SELinux, seccomp, PaX) operan restringiendo capacidades a nivel de politica, aceptando que ciertos programas legitimos necesitaran excepciones. La defensa perfecta implicaria un kernel que entiende intencion, lo cual es, por ahora, un problema abierto.

---

*Investigacion realizada como parte del proyecto [Black Hat Zig](https://github.com/JorgeBeritan) — documentacion de tecnicas ofensivas a nivel de syscall en Linux.*
