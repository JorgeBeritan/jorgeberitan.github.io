---
title: "Planificacion: Implant Fileless para Linux"
date: 2026-10-14
description: "Arquitectura y diseno de un implant fileless con capacidad de migracion usando exclusivamente syscalls directas en Zig."
tags: ["linux", "syscalls", "implant", "fileless", "zig", "offensive-security", "architecture"]
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

## 1. Motivacion

A lo largo de esta serie se implementaron cuatro tecnicas de forma aislada: syscalls directas, inspeccion de memoria via `/proc`, ejecucion dinamica con `mprotect`, ejecucion sin archivo con `memfd_create`, e inyeccion de procesos con `ptrace`. Cada una demostro una capacidad individual.

Este documento de planificacion responde una pregunta natural: **¿que sucede cuando estas primitivas se componen en una sola herramienta?**

El resultado es un implant — un programa que mantiene acceso persistente a un sistema, ejecuta comandos, y resiste la deteccion. No como concepto teorico: como codigo funcional donde cada componente utiliza exclusivamente las primitivas que ya se implementaron y documentaron.

---

## 2. Principios de Diseno

### 2.1 Cero dependencia de libc

El implant no invoca funciones de libc en ningun momento. Toda operacion pasa por syscalls directas usando `std.os.linux.syscallN`. El proposito es operacional concreto:

- **LD_PRELOAD no puede interceptarlo.** Un defensor que hookee `write()`, `connect()`, o `execve()` via LD_PRELOAD no ve nada porque el implant nunca llama a esas funciones de libc. Llama directamente al kernel.
- **Las herramientas de tracing basadas en libc no lo detectan.** `ltrace` instrumenta llamadas a librerias compartidas. Si no hay llamadas a librerias compartidas, `ltrace` no reporta nada.
- **Reduce la superficie de deteccion.** Menos dependencias significa menos puntos donde un EDR puede insertar hooks.

### 2.2 Sin presencia en disco

El binario del implant nunca existe como archivo en el filesystem. Se carga y ejecuta exclusivamente a traves de `memfd_create` + `execve` via `/proc/self/fd/N`. La unica presencia persistente es en la memoria del proceso.

### 2.3 Capacidad de migracion

El implant puede transferir su ejecucion a otro proceso mediante `ptrace`. Esto significa que incluso si el proceso original que lo cargo es terminado, el implant puede continuar operando dentro de un proceso legitimo del sistema.

### 2.4 Comunicacion directa

La conexion al C2 se establece usando syscalls de socket directas (`socket`, `connect`, `read`, `write`). No se utiliza la capa de red de la stdlib de Zig.

---

## 3. Arquitectura

El sistema se compone de tres piezas independientes:

### 3.1 Loader (dropper)

**Responsabilidad:** Cargar el implant en memoria y ejecutarlo sin tocar disco.

**Flujo:**
1. Contiene el binario del implant embebido en tiempo de compilacion (`@embedFile`)
2. Crea un memfd con `memfd_create`
3. Escribe el ELF del implant al memfd
4. Ejecuta via `execve("/proc/self/fd/N")`
5. El proceso del loader se reemplaza completamente por el implant

**Caracteristica clave:** Despues de `execve`, el loader deja de existir. El proceso que queda corriendo ES el implant, pero cargado desde memoria. Si un investigador lista procesos, ve un proceso sin binario en disco asociado.

### 3.2 Implant (nucleo)

**Responsabilidad:** Mantener comunicacion con el C2, ejecutar comandos, y persistir en el sistema.

**Capacidades:**

| Comando | Que hace | Syscalls involucradas |
|---|---|---|
| `info` | Reporta PID, UID, hostname, directorio de trabajo | `getpid`, `getuid`, `uname`, `getcwd` |
| `exec <cmd>` | Ejecuta un comando y retorna el output | `fork`, `execve`, `pipe`, `read`, `wait4` |
| `maps` | Lee y envia `/proc/self/maps` del proceso actual | `openat`, `read`, `close` |
| `migrate <pid>` | Inyecta el implant en otro proceso via ptrace | `ptrace`, `wait4` |
| `exit` | Cierra la conexion y termina limpiamente | `close`, `exit` |

**Flujo de ejecucion principal:**
1. Establece conexion TCP reversa al C2 (`socket` → `connect`)
2. Entra en un loop de recepcion de comandos
3. Parsea cada comando recibido
4. Ejecuta la operacion correspondiente
5. Envia el resultado al C2 por el mismo socket
6. Repite hasta recibir `exit`

### 3.3 C2 Listener

**Responsabilidad:** Recibir la conexion del implant y proveer una interfaz de comandos.

**Implementacion:** Para la primera version, `netcat` (`nc -lvp <puerto>`) es suficiente. El protocolo es texto plano sobre TCP. En una version posterior, se puede implementar un C2 dedicado en Zig con soporte para multiples sesiones, encriptacion, y un protocolo binario.

---

## 4. Perspectiva Ofensiva

### Ventajas operacionales

**Invisibilidad en disco:** El antivirus basado en firmas escanea archivos en el filesystem. Si no hay archivo, no hay firma que matchear. El implant existe solo en memoria, donde la mayoria de los AV tradicionales no buscan.

**Evasion de hooks de userspace:** Las herramientas de monitoreo que operan a nivel de libc (LD_PRELOAD hooks, library interposition) no ven las operaciones del implant. Solo `strace` (que usa ptrace sobre el proceso) o instrumentacion a nivel de kernel (eBPF, kprobes) pueden observar las syscalls directas.

**Migracion entre procesos:** Si el proceso original es sospechoso o esta a punto de ser terminado, el implant puede migrar a un proceso del sistema (`sshd`, `cron`, `apache2`). Despues de la migracion, la actividad de red y de ejecucion de comandos se atribuye al proceso legitimo, no al implant.

**Bajo footprint:** Un implant escrito en Zig con `ReleaseSmall` y sin stdlib de red pesa pocos kilobytes. Menos bytes en memoria significa menos probabilidad de deteccion por escaneo de memoria.

### Limitaciones

**strace lo ve todo.** Un administrador que corra `strace -p <pid>` sobre el proceso del implant ve cada syscall en tiempo real. No hay forma de evitar esto desde userspace sin rootkit a nivel de kernel.

**eBPF lo ve todo.** Los probes de eBPF se ejecutan dentro del kernel. No importa si el implant usa libc o syscalls directas — el kernel ve ambas. Un sistema con buena telemetria de eBPF detecta la actividad.

**`/proc/<pid>/exe` lo delata.** El link simbolico apunta a `memfd:nombre` o muestra `(deleted)`. Este es un indicador forense solido de fileless execution.

**La conexion de red es visible.** `ss` y `netstat` muestran la conexion TCP establecida. El trafico puede ser capturado con `tcpdump`. Sin encriptacion y sin tunelizado, el contenido de los comandos viaja en texto plano.

---

## 5. Perspectiva Defensiva

### Indicadores de compromiso

| Indicador | Donde buscarlo | Confiabilidad |
|---|---|---|
| `/proc/<pid>/exe` apunta a `memfd:*` | Escaneo periodico de `/proc/*/exe` | Alta |
| Conexion TCP saliente a IP/puerto inusual | `ss -tnp`, logs de firewall | Media |
| Proceso sin `libc` en maps pero con actividad de red | `/proc/<pid>/maps` | Media-alta |
| `ptrace` ATTACH desde proceso no-debugger | auditd, eBPF hooks en syscall 101 | Alta |
| `fork`+`execve` desde proceso que normalmente no ejecuta | Monitoreo comportamental | Media |

### Reglas de deteccion propuestas

**auditd:**
- Monitorear `memfd_create` (syscall 319) — cualquier invocacion merece registro
- Monitorear `execveat` (syscall 322) y `execve` donde el path contenga `/proc/self/fd/`
- Monitorear `ptrace` ATTACH (syscall 101, primer arg = 16) desde procesos no-debugger

**eBPF:**
- Tracepoint en `sys_enter_memfd_create` → registrar proceso y nombre del memfd
- Tracepoint en `sys_enter_execve` → alertar si path matchea `/proc/*/fd/*` o `/memfd:*`
- Correlacionar: si el mismo PID hace `memfd_create` seguido de `execve` con fd path, es fileless execution con alta probabilidad

**Escaneo periodico:**
- Recorrer `/proc/*/exe` buscando entries que contengan "memfd" o "(deleted)" sin un binario correspondiente en disco
- Comparar `/proc/<pid>/maps` con las librerias esperadas para ese tipo de proceso

### Mitigacion

- **seccomp-bpf:** Bloquear `memfd_create` y `ptrace` para procesos que no los necesitan
- **Yama ptrace_scope = 2 o 3:** Restringir ptrace a CAP_SYS_PTRACE o deshabilitarlo completamente
- **SELinux/AppArmor:** Politicas que restrinjan ejecucion desde memfd y tracing entre procesos
- **Network segmentation:** Detectar y bloquear conexiones salientes no autorizadas en el firewall perimetral

---

## 6. Plan de Desarrollo Incremental

### Fase 1 — Implant core (conexion + comandos basicos)
- Socket TCP reverso via syscalls directas
- Comando `info` (PID, UID, hostname)
- Comando `exec` (fork + execve + captura de output)
- Probar con `netcat` como C2

### Fase 2 — Reconocimiento
- Comando `maps` (leer /proc/self/maps y enviarlo)
- Comando `ls` / `pwd` via syscalls directas

### Fase 3 — Fileless delivery
- Compilar el implant como binario separado
- Implementar el loader con `memfd_create`
- Integrar y probar el flujo completo: loader → memfd → implant corriendo

### Fase 4 — Migracion
- Comando `migrate <pid>` usando ptrace injection
- Guardar y restaurar estado del proceso victima
- Verificar que la victima continua ejecutando normalmente post-migracion

### Fase 5 — Integracion y hardening
- Probar todos los flujos end-to-end
- Optimizar tamanio del binario (`ReleaseSmall`)

---

## 7. Estructura de Archivos

```
05-fileless-implant/
├── implant/
│   ├── build.zig
│   └── src/
│       └── main.zig          # Nucleo del implant
├── loader/
│   ├── build.zig
│   └── src/
│       └── main.zig          # Loader con memfd_create
└── c2/
    ├── build.zig
    └── src/
        └── main.zig          # Listener (fase posterior)
```

---

*Documento de planificacion para el proyecto [Black Hat Zig](https://github.com/JorgeBeritan) — implementacion de tecnicas ofensivas a nivel de syscall en Linux.*
