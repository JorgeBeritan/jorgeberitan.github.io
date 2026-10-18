---
title: "Fileless Implant: Primitive Composition as a Weapon"
date: 2026-10-16
description: "Analysis of how the composition of Linux kernel primitives (mprotect, memfd_create, ptrace) produces emergent offensive capabilities."
tags: ["linux", "syscalls", "implant", "fileless", "ptrace", "composition", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

**Prerequisites:** [mprotect as an Attack Vector](/black-hat-zig/mprotect-ejecucion-dinamica-de-codigo-en-linux/) · [memfd_create and Fileless Execution](/black-hat-zig/memfd-create-ejecucion-sin-archivo-en-linux/) · [ptrace and Process Injection](/black-hat-zig/ptrace-inyeccion-de-procesos-en-linux/)

---

## Summary

The three previous research pieces in this series documented individual primitives: `mprotect` for dynamic code execution, `memfd_create` for eliminating disk presence, and `ptrace` for injecting into foreign processes. Each demonstrated an isolated capability with limited scope. This research documents what happens when those primitives stop being independent exercises and are composed into a single tool: a fileless implant with migration capability. The result is not the sum of its parts — it is a qualitative leap in capability that is only possible when each primitive is understood deeply enough to integrate them.

---

## 1. The Composition Argument

There is a fundamental difference between knowing individual techniques and knowing how to compose them.

Whoever understands `memfd_create` can execute a binary without disk. Whoever understands `ptrace` can inject into another process. But whoever understands both can execute a binary without disk *inside a process that is not their own*. The combination produces a capability that neither offers on its own.

This principle — that the composition of primitives generates emergent capabilities — is central to offensive security. Frameworks like Metasploit and Cobalt Strike apply it internally: they combine in-memory loading, process injection, covert communication, and persistence into integrated flows. The difference is that those frameworks abstract the composition. Their users select options from a menu. The internal machinery coordinates the primitives.

The question motivating this research is not "how do I use these techniques" but **"what emerges when they are combined, and why is that combination more than the sum of its parts."**

---

## 2. Implant Anatomy

### 2.1 The Execution Chain

The system operates as a sequence of three stages, each built on the previous one:

**Stage 1 — Diskless loading.** A loader contains the implant binary embedded in its own data section. Upon execution, it creates an anonymous file descriptor in memory via `memfd_create`, writes the implant binary to that descriptor, and executes it through the virtual path `/proc/self/fd/N`. The loader process is completely replaced by the implant. After this transition, the loader ceases to exist and the implant is running in memory with no file on the filesystem backing it.

**Stage 2 — Operation.** The implant establishes a reverse TCP connection using direct socket syscalls. It enters a command reception and dispatch cycle. Every operation — from reporting system information to executing commands or inspecting the memory map — is implemented exclusively with syscalls, never invoking libc functions.

**Stage 3 — Migration.** When the decision is made to move execution to another process, the implant uses `ptrace` to inject a reverse connection shellcode into the target process. The shellcode creates its own network connection, redirects the process's standard descriptors to the socket, and replaces the process image with an interactive shell. The original implant process can continue operating or terminate — presence persists in the new process.

Each stage depends on the previous one: diskless loading ensures no filesystem presence, operation via direct syscalls avoids userspace hooks, and migration allows execution to survive the original process's termination.

### 2.2 The Absence of libc as a Design Decision

The decision not to use libc has concrete operational consequences.

When a program calls `connect()` through libc, the call goes through the Procedure Linkage Table (PLT), which resolves the symbol in the shared library. A defender hooking the PLT or using `LD_PRELOAD` to interpose their own version of `connect()` intercepts the call. `ltrace` logs every library function invocation. An EDR monitoring libc calls sees all the process's network activity.

When the same program invokes the `connect` syscall directly (number 42 on x86_64, arguments in registers, `syscall` instruction), none of these mechanisms detect it. There is no PLT to hook because there is no symbol resolution. There is no shared library to interpose because none is used. `ltrace` reports nothing because there are no library calls. The operation is invisible to every tool operating at the userspace level.

The only layer that sees the operation is the kernel itself: `strace` (which uses ptrace internally), auditd, and eBPF. These are tools of significantly higher sophistication than userspace defenses, and not all organizations have them configured for active monitoring.

### 2.3 Commands as Primitives

Each implant command is a decision about the tradeoff between visibility and flexibility.

Commands the implant implements natively — system information, memory map reading, directory listing — operate within the implant's process without creating child processes. From a process monitor's perspective, nothing observable happens: a process reads its own `/proc/self/maps` or invokes `getdents64` on a directory. These are operations any process performs as part of normal functioning.

Arbitrary command execution requires a different tradeoff. To execute an external program, the implant needs to create a child process (`fork`), redirect its output to a pipe, execute the program (`execve`), capture the output, and send it. Each of these steps is observable: `fork` creates a new process visible in `ps`, `execve` loads a binary that can be inspected, the parent-child chain is visible in the process tree.

A well-designed implant minimizes the need for external execution by implementing as much functionality natively as possible. Each native command is an invisible operation. Each external execution is an observable operation. The balance between both defines the implant's detection profile.

---

## 3. Migration as an Emergent Capability

### 3.1 Why Migrate

Migration exists because every process has a limited lifecycle.

The process executing the implant can be terminated by an administrator, closed by a system timeout, or identified as anomalous by an EDR. If the only execution instance of the implant resides in that process, termination means total loss of access.

Migration solves this problem in the most direct way possible: it moves execution to a process that is less likely to be terminated. A system service like `sshd`, `cron`, or a web server is an ideal candidate: they are long-lived processes, expected on the system, and whose network activity (in the case of network services) masks the payload's communications.

### 3.2 The Mechanics of Composition

Migration is where the composition of primitives manifests most clearly.

To migrate, the implant needs:

1. **Target knowledge.** A destination process is selected. The implant can assist in this selection by showing the process tree or memory maps of candidate processes — capabilities implemented using the same `/proc` reading syscalls documented in this series.

2. **Remote process control.** The implant uses `ptrace` to attach to the destination process, halt its execution, read its registers and memory, write the payload, and resume execution.

3. **Independent communication establishment.** The injected payload cannot depend on the original implant's connection — that connection belongs to the original process and is not transferable. The payload needs to establish its own network connection. This means the injected shellcode must contain the complete logic for `socket` + `connect` + descriptor redirection, implemented in position-independent machine code.

4. **Process replacement.** Once the payload has its own connection, it executes `execve` to replace the destination process's image. The result is an interactive shell running inside a process that, from the process listing's perspective, has not changed: same PID, same PPID, same user. Only its content is different.

### 3.3 The Syscall Restart Issue

A technical detail that does not emerge until real composition is attempted: when a process is in the middle of a blocking syscall (like `nanosleep` in a `sleep` process), the kernel records the syscall number in a special field of the register structure (`orig_rax`). If the process is interrupted and then resumed, the kernel may attempt to restart the original syscall instead of executing from the new instruction pointer.

This behavior is correct for the intended use case (debugging): if a debugger halts a process during a `read()` and resumes it, the user expects the `read()` to continue. But for injection, it is a problem: the execution should jump to the shellcode, not return to the interrupted `nanosleep`.

The solution is to invalidate the `orig_rax` field by writing a negative value before resuming the process. This tells the kernel there is no pending syscall to restart.

This is an example of knowledge that is only acquired through the practice of composition. None of the individual research pieces needed to consider the interaction between syscall interruption and code injection. Only when both operations are combined in a real flow — interrupting a blocked process to inject shellcode — does the problem manifest.

---

## 4. Offensive Perspective: The Sum of Evasions

### Layers of Invisibility

Each primitive contributes an evasion layer. Composed, the layers multiply:

**No disk presence.** The implant was loaded via `memfd_create`. It does not exist as a file on any filesystem. File scanners (signature-based antivirus, file integrity monitoring) have nothing to scan. The only static indicator is `/proc/<pid>/exe` pointing to `memfd:name (deleted)`.

**No libc hooks.** Every operation uses direct syscalls. `LD_PRELOAD`, library interposition, and `ltrace` are blind to the implant's activity. An entire level of defensive instrumentation is neutralized.

**No new process after migration.** After migrating, execution resides in a pre-existing process. No new binary, no new command line, no new PID. The victim process retains its external identity while executing injected code.

**Silent native operations.** Commands implemented via direct syscalls (directory reading, memory inspection, system information) generate no child processes and no invocations of external programs. They are indistinguishable from any process's normal operations.

None of these layers is absolute. Each has detectable indicators. But a defender who wants to detect the implant needs to cover *all* layers: monitor `/proc/*/exe` for fileless execution, instrument syscalls via eBPF for libc-free activity, audit `ptrace` for injection, and analyze behavior for anomalous operations. Omitting any layer leaves a blind spot.

### What a Framework Abstracts

When a framework like Metasploit executes a meterpreter migration between processes, it internally executes exactly these primitives. The difference is the level of abstraction: `migrate <pid>` is selected and the framework coordinates the attach, injection, and execution.

Implementing the same capability from raw primitives reveals the decision points that the abstraction hides:

- At what memory address is the injection performed? The framework chooses automatically. Without abstraction, one must understand why the current RIP address is used (because that memory is already executable).
- How is partial word writing handled? POKETEXT writes 8 bytes at a time. If the shellcode is not a multiple of 8, the last write needs a merge operation with the original bytes.
- What happens if the target is in a blocking syscall? The `orig_rax` problem and the kernel's syscall restart policy must be discovered.

Each of these decisions is invisible to the framework user and mandatory for whoever implements the tool.

---

## 5. Defensive Perspective: Detecting the Composition

### 5.1 Indicators by Layer

| Layer | Indicator | Where to Look | Reliability |
|---|---|---|---|
| Fileless | `/proc/<pid>/exe` → `memfd:*` | Periodic scan of `/proc/*/exe` | High |
| No libc | Process without `libc.so` in `/proc/<pid>/maps` but with network activity | Correlation maps vs connections | Medium-high |
| Migration | `ptrace ATTACH` from non-debugger process | auditd, eBPF on syscall 101 | High |
| Shellcode | RIP transition to unexpected region post-ptrace | Register monitoring pre/post detach | Low (requires deep instrumentation) |
| C2 connection | Outbound TCP connection to unusual IP/port | `ss -tnp`, firewall logs | Medium |
| Execution | `fork`+`execve` from process that normally does not execute | Behavioral baseline | Medium |

### 5.2 Detection by Correlation

Individual indicators generate false positives. A process without libc in maps is not necessarily malicious (static binaries exist). A ptrace invocation is not necessarily injection (debuggers exist). An outbound TCP connection is not necessarily C2 (legitimate applications make connections).

Effective detection of the composite implant requires **temporal and contextual correlation** of multiple indicators:

- A process whose `/proc/<pid>/exe` points to a memfd **AND** has an outbound TCP connection **AND** has no libc in its memory map → high probability of fileless implant.
- A system service that receives a `ptrace ATTACH` **AND** shortly after establishes a new TCP connection that did not exist before → high probability of post-injection migration.
- A process executing `fork`+`execve` of `/bin/sh` **AND** whose stdin/stdout descriptors point to a socket **AND** that socket was recently created → high probability of reverse shell.

No individual indicator justifies a high-priority alert. The combination of two or more, within a narrow temporal window, does. Detection systems that correlate multiple telemetry sources (SIEM with correlation rules, EDR with behavioral detection) are designed for exactly this type of pattern.

### 5.3 The Temporal Blind Spot

The detection window for migration is particularly narrow. The complete sequence — attach, injection, execution, detach — can complete in milliseconds. A system sampling `/proc/<pid>/status` every second has a low probability of capturing the `TracerPid` field during the injection window.

After migration, the victim process has been replaced by a shell. Its `/proc/<pid>/exe` now points to `/bin/sh` (or `/bin/dash`), which is the most persistent indicator. But a process executing `/bin/sh` is not inherently suspicious — system scripts, cron jobs, and interactive sessions use shells constantly.

The most robust detection does not look for the injection event (too brief) but for its **consequences**: a process that changed its binary (`exe` points to something different from what the process originally was), a service that now has network connections it did not have before, or a change in the syscall pattern of a long-lived process.

### 5.4 Structural Mitigations

**seccomp-bpf:** Restrict `memfd_create`, `ptrace`, and `execveat` for processes that do not need them. Most production services never use these syscalls, so the operational impact is minimal. Modern containers already drop `SYS_PTRACE` by default.

**Yama ptrace_scope:** Scope 2 or 3 blocks ptrace for unprivileged users. This prevents migration unless `CAP_SYS_PTRACE` or root is held.

**Namespaces and cgroups:** Process isolation in PID and network namespaces limits migration scope. An implant inside a container cannot migrate to processes outside the container (without an additional container escape).

**Process integrity monitoring:** Periodically verify that `/proc/<pid>/exe` of critical services points to the expected binary. Any unexpected change warrants immediate investigation.

**Network segmentation:** Detect and alert on outbound connections from services that should not initiate connections. An `sshd` that suddenly establishes a TCP connection to a high port on an external IP is highly suspicious.

---

## 6. Final Reflection

This research completes an arc that began with the most basic question — "how do I ask the kernel to do something" — and culminates in a system that composes multiple answers into a cohesive tool.

Each individual primitive is a kernel capability designed for a legitimate purpose. `memfd_create` exists for secure shared memory. `ptrace` exists for debugging. Socket syscalls exist for network communication. `fork` and `execve` exist for creating and executing processes.

The central lesson has not changed since the first research piece: **the system works exactly as specified**. No bugs are exploited, no vulnerabilities are leveraged, no unexpected kernel behavior is involved. What exists is a composition of public interfaces that produces an effect the designers did not contemplate as a primary use case.

Defense against this composition cannot be based on blocking individual primitives — doing so would break legitimate functionality that depends on them. It must be based on detecting composition patterns: the temporal correlation of operations that are individually benign but that combined indicate adversarial activity.

This is the irreducible problem of systems security: a kernel that exposes primitives powerful enough to build useful tools is, by definition, a kernel that exposes primitives powerful enough to build offensive tools. The line between both is not in the primitives — it is in the intent and context of whoever composes them.

---

*Research conducted as part of the [Black Hat Zig](https://github.com/JorgeBeritan) project — documentation of offensive techniques at the syscall level on Linux.*
