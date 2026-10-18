---
title: "Process Injection on Linux: ptrace as a Total Control Tool"
date: 2026-10-12
description: "Using the ptrace syscall to read, write, and execute code in the context of a foreign process on Linux."
tags: ["linux", "syscalls", "ptrace", "process-injection", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

**Prerequisites:** [mprotect as an Attack Vector](/black-hat-zig/mprotect-ejecucion-dinamica-de-codigo-en-linux/) · [memfd_create and Fileless Execution](/black-hat-zig/memfd-create-ejecucion-sin-archivo-en-linux/)

---

## Summary

The techniques documented previously in this series — dynamic shellcode execution via `mprotect` and fileless execution via `memfd_create` — operate within the process's own memory space. This research crosses that boundary: it documents the use of the `ptrace` syscall to read, write, and execute code in the context of a foreign process. It is the convergence of all primitives studied so far and represents the most complete offensive capability the Linux kernel offers from userspace.

---

## 1. The Conceptual Leap

There is a qualitative difference between executing code in your own process and executing code in someone else's process.

In the previous techniques, memory is created, the payload is written, and it is executed. The process performing the execution is the same one that was created. A defender listing active processes would see an unknown process — a binary that should not be there.

Process injection eliminates that visibility. The payload executes inside a process **that already existed before the operation**: a web server, a system daemon, a user process. From the perspective of a process listing, nothing changed. No new process, no unknown binary, no suspicious command line.

The question this technique answers is not "how do I execute my code" but **"how do I make a legitimate process execute arbitrary code without anyone noticing the difference."**

---

## 2. The Primitive: ptrace

### What it is and why it exists

`ptrace` (process trace) is a syscall that allows one process — the **tracer** — to observe and control the execution of another process — the **tracee**. It is the foundation upon which all debuggers on Linux are built: GDB, LLDB, strace, ltrace. Without `ptrace`, interactive process debugging on Linux would not be possible.

The syscall offers a set of operations:

| Operation | What it allows |
|---|---|
| ATTACH | Connect to an existing process and halt its execution |
| GETREGS | Read all processor registers of the tracee |
| SETREGS | Write the processor registers of the tracee |
| PEEKTEXT | Read one word (8 bytes) from the tracee's memory |
| POKETEXT | Write one word (8 bytes) to the tracee's memory |
| CONT | Resume the tracee's execution |
| DETACH | Disconnect from the tracee and let it continue |

Each of these operations was designed for debugging. GETREGS lets GDB display the processor state. PEEKTEXT lets it inspect memory. POKETEXT lets it insert breakpoints. CONT lets it execute instruction by instruction.

The critical point is that **the interface does not distinguish between debugging use and injection use**. The same operations that allow GDB to insert a breakpoint (POKETEXT with byte 0xCC) allow an attacker to write arbitrary shellcode.

### Comparison with Windows

On Windows, the equivalent capabilities are distributed across multiple APIs:

- `OpenProcess` → obtain a handle to the process
- `ReadProcessMemory` / `WriteProcessMemory` → read/write memory
- `GetThreadContext` / `SetThreadContext` → read/write registers
- `CreateRemoteThread` / `NtCreateThreadEx` → create a thread in the remote process
- `VirtualAllocEx` / `VirtualProtectEx` → manage remote memory

That is at least six coordinated APIs to achieve what `ptrace` does with a single syscall and different operation codes. The monitoring surface on Windows is wider precisely because there are more interception points. On Linux, everything goes through a single point: syscall 101.

This has direct defensive implications. On Windows, an EDR can hook `CreateRemoteThread` specifically to detect injection without affecting debugging. On Linux, monitoring `ptrace` to detect injection inevitably detects (and potentially interferes with) legitimate debugging.

---

## 3. The Injection Flow

### Phase 1 — Target selection

Before injecting, a target process must be chosen. The selection depends on the objective:

- **Persistence**: a daemon that is always running (sshd, cron, a web service).
- **Evasion**: a process that naturally generates network traffic (a browser, a DNS client) to camouflage C2 communications.
- **Escalation**: a process running with higher privileges.

The ideal process is one that is common, long-lived, and whose normal activity masks the payload's activity.

### Phase 2 — Attach and halt

`ptrace(ATTACH, pid)` is invoked. The kernel sends a SIGSTOP signal to the tracee, halting its execution. `waitpid` is used to confirm the tracee has stopped.

This is the most visible moment of the operation. The victim process freezes briefly. If the process is handling active connections or critical timers, the pause can cause observable effects (timeouts, dropped connections).

### Phase 3 — State reconnaissance

The tracee's registers are read with GETREGS. The most important register is **RIP** (instruction pointer): it indicates exactly where the process was executing when it was halted. **RSP** (stack pointer) and all other general-purpose registers are also captured.

This complete state is saved. It is the "snapshot" of the process before injection, and will be needed for subsequent restoration.

### Phase 4 — Memory preservation

Before writing shellcode, the original bytes at the address where injection will occur (typically the current RIP address) are read and saved. Without these saved bytes, the process cannot be restored to its original state.

The read is done with PEEKTEXT, which returns one word (8 bytes) per invocation. For shellcode of N bytes, ceil(N/8) invocations are needed.

### Phase 5 — Payload writing

The shellcode is written to the tracee's memory using POKETEXT, which writes one word per invocation. The shellcode overwrites the original instructions at the RIP address.

A technical subtlety: POKETEXT writes complete 8-byte words. If the shellcode is not a multiple of 8, the last write needs to be a "merge" operation: read the original word with PEEKTEXT, replace only the necessary bytes, and write the combined word with POKETEXT. Without this care, bytes adjacent to the shellcode are corrupted.

### Phase 6 — Execution

`ptrace(CONT, pid)` is invoked. The tracee resumes execution, but now RIP points to the injected shellcode. The processor decodes and executes the shellcode as if it were the process's original instructions.

The shellcode terminates with an `int3` instruction (byte 0xCC). This instruction generates a breakpoint exception (SIGTRAP) that halts the tracee and notifies the tracer. It is the return mechanism: the shellcode signals "I'm done" without needing to know a return address.

An important design point: in the `mprotect` execution documented previously, the shellcode used `ret` to return to the caller. That was possible because there was a prior `call` that deposited a return address on the stack. In ptrace injection, there is no `call` — RIP was modified directly. There is no return address on the stack. `int3` solves this problem: it halts execution and returns control to the tracer through the kernel's signal mechanism, not through the stack.

### Phase 7 — Restoration

After the shellcode executes and the tracee halts on `int3`, the tracer:

1. Restores the original bytes in memory (POKETEXT with the bytes saved in Phase 4).
2. Restores the original registers (SETREGS with the values saved in Phase 3).

The victim process is left in the exact state it was in before injection. Its memory contains the original instructions, its registers point where they pointed, and its stack was not modified.

### Phase 8 — Detach

`ptrace(DETACH, pid)` is invoked. The tracing relationship dissolves. The tracee continues its normal execution from the exact point where it was halted.

If the operation was performed correctly, the victim process has no way of knowing it was injected. Its execution continues without errors, without crashes, without inconsistencies in its internal state.

---

## 4. The Stealth Question

### What evidence remains

**During injection:**
- The victim process has the `t` (traced) state in `/proc/<pid>/status`. Any tool that queries this field sees the process is being traced.
- The `TracerPid` field in `/proc/<pid>/status` shows the tracer's PID.
- The pause in the tracee's execution may be observable if it handles active connections.

**After detach:**
- `TracerPid` returns to 0.
- The process state returns to normal.
- Memory and registers were restored.
- **No persistent evidence remains in the process.** Without active monitoring during the injection window, there is no artifact that a post-hoc analysis can find.

### The temporal window

The detection window is the time between ATTACH and DETACH. For a small shellcode, this time can be microseconds. A defender not actively sampling `/proc/<pid>/status` at that precise interval will not detect the injection.

This creates a fundamental asymmetry: the attacker controls the window's duration, and the defender needs to be observing during that specific window. The attacker needs to succeed once; the defender needs to be watching all the time.

---

## 5. Complete Attack Chain

This technique does not exist in isolation. It represents the culmination of the primitives documented in this series, and its real power emerges when they are chained:

### Reconnaissance: /proc/self/maps

Before injecting, `/proc/<pid>/maps` of the victim process is read to understand its memory layout. Executable regions (where RIP could be), writable regions (alternatives for depositing the payload), and the presence of specific libraries (for resolving functions dynamically) are identified.

### Dynamic execution: mprotect

If a payload larger than the space available at the current RIP region needs to be injected, `ptrace` can be used to invoke `mmap` in the victim's context (writing a short shellcode that calls `mmap`, executing it, then writing the real payload in the new region). Then `mprotect` is used to make that region executable.

### Fileless delivery: memfd_create

The final payload can be a complete ELF loaded via `memfd_create` inside the victim process. A minimal loader is injected that creates a memfd, writes the ELF, and executes it with `execveat` or maps it in memory. The payload binary never touches disk.

### The complete chain

1. Read `/proc/<pid>/maps` → memory layout reconnaissance
2. `ptrace ATTACH` → take control of the process
3. Inject a stub that calls `mmap` → create space for the payload
4. `mprotect` the new region → make it executable
5. Write the real payload (or a `memfd_create` loader) → deposit the code
6. Modify RIP → execute the payload
7. Restore and DETACH → leave no trace

Each technique individually has limited scope. Chained together, they represent the capability to execute an arbitrary program inside a legitimate process without any file on disk or any new visible process.

---

## 6. Defensive Perspective

### Real-time detection

**ptrace monitoring via auditd/eBPF:**
The most direct signal is a `ptrace(ATTACH)` invocation from a process that is not a known debugger. An auditd rule that logs syscall 101 with argument ATTACH (16) captures every injection attempt. The challenge is distinguishing legitimate debugging attach from malicious attach — the context of the invoking process is key.

**Periodic TracerPid scanning:**
A security agent that periodically reads `/proc/<pid>/status` can detect processes being traced. If a critical service (sshd, nginx, a database process) has a non-zero TracerPid and there is no known debugging session, the alert is high priority.

**Process state monitoring:**
The `t` (traced/stopped) state in `/proc/<pid>/stat` indicates active tracing. A process transitioning to state `t` without an administrator having started a debugger warrants investigation.

### Prevention

**Yama LSM (ptrace_scope):**
The kernel's Yama module implements restrictions on who can use ptrace:

- **Scope 0:** No restrictions. Any process can trace any other with the same UID.
- **Scope 1:** Direct descendants only. A process can only trace its children.
- **Scope 2:** Administrators with CAP_SYS_PTRACE only.
- **Scope 3:** ptrace completely disabled.

Most server-oriented distributions use scope 1 by default. Scope 2 or 3 blocks the technique for unprivileged users, but also prevents normal debugging.

**seccomp-bpf:**
A seccomp filter can block `ptrace` entirely for processes that do not need it. Modern containers (Docker, Kubernetes) already apply this by default: the `SYS_PTRACE` capability is removed from the container's capability set.

**PID namespaces:**
If the potential victim runs in a different PID namespace than the attacker, `ptrace` cannot reach it. Namespace isolation is an effective barrier against cross-context injection.

**SELinux/AppArmor:**
Both frameworks can define policies that restrict which processes can be traced and by whom. A well-configured policy can allow GDB to trace user processes but deny tracing between system services.

### The limitation of the defensive approach

The fundamental challenge is that `ptrace` is a critical ecosystem tool. Debuggers need it. Performance tracers need it. Some sandboxing tools need it. Blocking it entirely breaks development and operations workflows.

Effective defense cannot be a binary switch (allow/block). It must be contextual: who is invoking ptrace? On which process? Under what circumstances? The answers to these questions require granular policies and active monitoring, not static rules.

---

## 7. Final Reflection

`ptrace` completes an arc that began with writing bytes to one's own memory and culminates in total control of foreign processes. Each step in this progression — `mprotect`, `memfd_create`, `ptrace` — added a new capability, and each capability was provided by the kernel through public, documented interfaces designed for legitimate use.

A system's security cannot be evaluated by looking at each component in isolation. `ptrace` is safe in the context of debugging. `memfd_create` is safe in the context of shared memory. `mprotect` is safe in the context of JIT compilation. It is the **composition** of these primitives with adversarial intent that generates the offensive capability.

An attacker does not discover vulnerabilities in these syscalls. They discover that, combined in a certain way, they produce an effect that the designers did not anticipate as a primary use case. The system works exactly as specified. The specification simply did not contemplate all possible uses.

---

*Research conducted as part of the [Black Hat Zig](https://github.com/JorgeBeritan) project — documentation of offensive techniques at the syscall level on Linux.*
