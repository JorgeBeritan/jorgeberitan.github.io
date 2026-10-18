---
title: "Ejecucion Sin Archivo en Linux: memfd_create como Primitiva de Fileless Execution"
date: 2026-10-10
description: "Uso de memfd_create para ejecutar binarios ELF completos sin que estos existan como archivos en el filesystem."
tags: ["linux", "syscalls", "memfd_create", "fileless", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

**Prerequisito:** [Ejecucion Dinamica de Codigo: mprotect como Vector de Ataque](/research/mprotect-ejecucion-dinamica-de-codigo-en-linux/)

---

## Resumen

Esta investigacion documenta el uso de la syscall `memfd_create` como primitiva para ejecutar binarios ELF completos sin que estos existan como archivos en el filesystem. La tecnica representa una evolucion natural respecto a la ejecucion dinamica de shellcode via `mprotect` documentada anteriormente: donde aquella tecnica permite ejecutar fragmentos de codigo maquina desde memoria, esta permite ejecutar **programas completos** sin dejar rastro en disco. Se analiza el mecanismo tecnico, su relacion con tecnicas analogas en Windows, y las estrategias de deteccion disponibles.

---

## 1. El Problema

La ejecucion de codigo via `mprotect` tiene una limitacion practica: el payload es shellcode crudo. Para operaciones complejas (persistencia, movimiento lateral, exfiltracion), se necesita ejecutar programas completos, no fragmentos de codigo maquina.

La ruta convencional para ejecutar un programa en Linux es:

1. Escribir el binario a disco.
2. Llamar a `execve` con la ruta del archivo.

El problema es evidente: el paso 1 deja un artefacto en el filesystem. Un archivo en disco puede ser escaneado por un antivirus, detectado por file integrity monitoring (AIDE, OSSEC, Tripwire), registrado por auditd, y recuperado en un analisis forense incluso despues de ser eliminado.

La pregunta es directa: **¿es posible ejecutar un programa sin que exista como archivo en disco en ningun momento?**

---

## 2. La Primitiva: memfd_create

### Origen y proposito legitimo

`memfd_create` fue introducida en Linux 3.17 (2014). Su proposito original es crear **archivos anonimos respaldados por memoria**. A diferencia de un archivo tradicional que reside en un filesystem montado, un memfd existe unicamente como un objeto del kernel en RAM.

Los casos de uso legitimos incluyen:

- **Memoria compartida entre procesos:** Mas seguro que `/dev/shm` porque el fd puede sellarse con `F_SEAL` para prevenir modificaciones.
- **Archivos temporales sin riesgo de colision:** No necesitan un directorio temporal ni un nombre unico.
- **Contenedores y sandboxing:** Sistemas como Docker y Flatpak los usan para pasar datos entre procesos aislados.

La syscall recibe dos argumentos: un nombre de debug (visible en `/proc/<pid>/fd/`) y flags opcionales. Retorna un file descriptor que se comporta como cualquier otro fd: se puede leer, escribir, mapear, y — criticamente — se puede pasar a `execveat` para ejecucion.

### La propiedad clave

Un memfd **no tiene entrada en ningun directorio del filesystem**. No existe en `/tmp`, no existe en `/dev/shm`, no existe en ningun punto de montaje. La unica forma de accederlo es a traves del file descriptor dentro del proceso que lo creo, o a traves de la entrada virtual `/proc/<pid>/fd/<N>` mientras el proceso esta vivo.

Si el proceso termina y ningun otro proceso heredo el fd, el memfd desaparece completamente. No hay nada que recuperar de disco porque nunca estuvo en disco.

---

## 3. El Mecanismo: De Bytes en Memoria a Proceso en Ejecucion

### Fase 1 — Creacion del contenedor

Se invoca `memfd_create` para obtener un fd anonimo. El flag `MFD_CLOEXEC` se aplica para que el fd se cierre automaticamente al ejecutar `execveat`. Esto es una medida de higiene: si el fd sobrevive al exec, el proceso hijo lo hereda y un investigador podria encontrarlo listando `/proc/<pid>/fd/`.

### Fase 2 — Carga del payload

El contenido de un binario ELF se escribe en el memfd usando la syscall `write`, exactamente como se escribiria a un archivo normal. El payload puede provenir de multiples fuentes: estar embebido en el propio loader, descargado de la red, desencriptado en runtime, o recibido a traves de un socket.

Lo relevante es que la escritura ocurre a un objeto de memoria del kernel, no a un bloque en un dispositivo de almacenamiento. No hay sector de disco que registre la operacion, no hay journal de filesystem que la persista, no hay cache de pagina vinculado a un inode en un dispositivo fisico.

### Fase 3 — Ejecucion

La syscall `execveat` (numero 322 en x86_64) es la variante moderna de `execve` que acepta un file descriptor en lugar de una ruta. Con el flag `AT_EMPTY_PATH`, le indica al kernel: "ejecuta el contenido referenciado por este fd, no busques ningun path".

El kernel procede exactamente como lo haria con un `execve` normal: verifica que el contenido es un ELF valido, carga los segmentos en memoria, configura el stack, y transfiere el control al entry point del programa. La unica diferencia es que el backing store del ELF es un objeto de memoria anonimo en vez de un archivo en un filesystem.

Desde la perspectiva del kernel, la operacion es completamente ordinaria. La distincion entre "archivo en disco" y "archivo en memoria" es una cuestion de backend de almacenamiento, no de legitimidad de la operacion.

---

## 4. Comparacion con Tecnicas Analogas en Windows

El ecosistema Windows tiene tecnicas con objetivos similares que resultan instructivas en comparacion.

### Process Herpaderping

Explota la separacion temporal entre la creacion de una seccion de memoria (NtCreateSection) y el escaneo del archivo por el software de seguridad. Se mapea el archivo como seccion, luego se sobrescribe el contenido del archivo en disco con datos benignos antes de que el AV lo inspeccione. El proceso ejecuta el contenido original, pero el archivo en disco muestra contenido inofensivo.

### Process Ghosting

Similar a Herpaderping pero mas agresivo: despues de mapear la seccion, el archivo se marca para eliminacion (delete-pending state) y se cierra el handle. El archivo desaparece del filesystem, pero la seccion permanece valida en memoria.

### La diferencia fundamental

Tanto Herpaderping como Ghosting dependen de una peculiaridad arquitectural de Windows: la creacion de procesos es un flujo de multiples pasos con estados intermedios explotables. El archivo existe en disco al menos brevemente — lo suficiente para mapearlo como seccion.

`memfd_create` en Linux es conceptualmente mas limpio: **el archivo nunca toca disco en ningun momento**. No hay ventana temporal de escaneo porque no hay artefacto en el filesystem que escanear. No se explota un gap entre pasos — se usa una primitiva disenada para operar exclusivamente en memoria.

La diferencia refleja las filosofias de diseno de ambos sistemas. Windows ofrece un modelo de creacion de procesos complejo con multiples capas de abstraccion, y la complejidad genera superficie de ataque en las transiciones entre capas. Linux ofrece primitivas simples y directas, y la superficie de ataque emerge de la potencia inherente de esas primitivas.

---

## 5. Indicadores y Deteccion

### Que ve el defensor

**En `/proc/<pid>/fd/`:**
Mientras el loader tiene el memfd abierto (antes de `execveat`), el fd aparece como un enlace simbolico a `memfd:<nombre>`. El nombre es el que se paso a `memfd_create`. Despues de `execveat` con `MFD_CLOEXEC`, el fd desaparece.

**En `/proc/<pid>/exe`:**
Aqui hay un indicador fuerte. Normalmente, `/proc/<pid>/exe` apunta al binario en disco que se ejecuto (por ejemplo, `/usr/bin/ls`). Para un proceso lanzado desde un memfd, apunta a una ruta virtual como `/memfd:<nombre> (deleted)`. La presencia de "memfd" en esta ruta es una senal clara de fileless execution.

**En los logs de auditd:**
La syscall `memfd_create` puede registrarse con una regla de auditoria. La combinacion `memfd_create` seguida de `execveat` en el mismo proceso es altamente sospechosa y practicamente nunca ocurre en uso legitimo normal.

### Estrategias de deteccion

**Monitoreo de `/proc/<pid>/exe`:**
Cualquier proceso cuyo enlace `exe` contenga "memfd" merece investigacion inmediata. Herramientas de EDR pueden escanear periodicamente esta ruta para todos los procesos activos. Este es el indicador mas confiable y dificil de evadir.

**Reglas de auditd/eBPF:**
Monitorear invocaciones de `memfd_create` (syscall 319) y `execveat` (syscall 322). La correlacion de ambas en el mismo proceso, especialmente si `execveat` usa `AT_EMPTY_PATH`, indica fileless execution con alta probabilidad.

**Analisis de contenido del memfd:**
Mientras el memfd existe, su contenido puede ser leido a traves de `/proc/<pid>/fd/<N>`. Un respondedor de incidentes puede capturar el payload antes de que el proceso termine y el memfd desaparezca. Esto requiere deteccion en tiempo real — una vez que el proceso muere, la evidencia se pierde.

**seccomp-bpf:**
Un filtro seccomp puede bloquear `memfd_create` para procesos que no la necesitan. Dado que la mayoria de los programas nunca usan esta syscall, la politica de bloqueo tiene bajo impacto en funcionalidad.

### La carrera contra el tiempo

La dificultad principal para el defensor es temporal. El memfd existe solo mientras el proceso lo mantiene abierto. Con `MFD_CLOEXEC`, el fd se cierra al ejecutar el payload. Si el proceso payload es efimero (ejecuta su tarea y termina), la ventana para capturar evidencia puede ser de milisegundos.

Un atacante sofisticado puede reducir esta ventana aun mas: ejecutar el payload, capturar su output via pipes, y terminar el proceso inmediatamente. Para cuando un escaner periodico revisa `/proc`, el proceso ya no existe.

---

## 6. Variantes y Evoluciones

### Carga desde red

En un escenario operacional real, el payload no estaria embebido en el loader. Se descargaria en runtime — desde un C2 via HTTPS, desde un recurso compartido, o desde un DNS tunnel. Los bytes viajan del socket directamente al memfd, sin tocar disco en ningun punto del camino.

### Encriptacion en transito

El payload puede almacenarse encriptado (en el loader o en el servidor C2) y desencriptarse en memoria antes de escribirlo al memfd. Esto agrega una capa adicional: incluso si un defensor captura el loader, el payload real no es visible sin la clave de desencriptacion.

### Encadenamiento con ptrace

En vez de ejecutar el payload en el propio proceso, se puede usar `ptrace` para inyectar el contenido del memfd en otro proceso ya existente. Esto combina fileless execution con process injection: el payload no solo no existe en disco, sino que se ejecuta dentro del contexto de un proceso legitimo.

---

## 7. Reflexion Final

`memfd_create` representa un punto interesante en la tension entre funcionalidad y seguridad del kernel Linux. Es una syscall util con casos de uso legitimos claros, pero su capacidad de crear objetos ejecutables que nunca tocan disco la convierte en una primitiva ofensiva de primera categoria.

A diferencia de las tecnicas de Windows que explotan gaps arquitecturales en flujos complejos, `memfd_create` es una herramienta directa: fue disenada para crear archivos en memoria, y eso es exactamente lo que hace un atacante. No hay exploit, no hay bug, no hay comportamiento inesperado. La syscall funciona perfectamente segun su especificacion.

La deteccion es posible — `/proc/<pid>/exe` apuntando a un memfd es un indicador fuerte — pero la mitigacion completa requiere decisiones de politica: ¿bloqueamos `memfd_create` para todos los procesos? ¿Solo para algunos? ¿Como manejamos los procesos legitimos que la necesitan?

Estas preguntas no tienen respuestas tecnicas puras. Son decisiones de gestion de riesgo que cada organizacion debe tomar en funcion de su superficie de ataque, su tolerancia al impacto operacional, y la madurez de su programa de seguridad.

---

*Investigacion realizada como parte del proyecto [Black Hat Zig](https://github.com/JorgeBeritan) — documentacion de tecnicas ofensivas a nivel de syscall en Linux.*
