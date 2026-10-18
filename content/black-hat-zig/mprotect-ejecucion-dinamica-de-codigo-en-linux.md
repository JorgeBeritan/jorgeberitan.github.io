---
title: "Dynamic Code Execution on Linux: mprotect as an Attack Vector"
date: 2026-10-08
description: "How the Linux kernel's memory management primitives can be repurposed to achieve arbitrary code execution at runtime."
tags: ["linux", "syscalls", "mprotect", "memory-management", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

## Summary

This research documents how the Linux kernel's memory management primitives, designed for legitimate use by JIT compilers and dynamic loaders, can be repurposed to achieve arbitrary code execution at runtime. The technique exploits no vulnerability: it operates entirely within the operating system's public interface. The complete flow, necessary conditions, and available detection and mitigation strategies are analyzed.

---

## 1. Starting Point

The fundamental goal of any post-exploitation offensive operation is to execute custom code within a process context. The question is not "how do I break the system" but **"what does the system offer me that I can use for my purposes?"**

Linux exposes all its functionality to userspace through syscalls. These are the contractual interface between programs and the kernel. They are not bugs, not backdoors: they are the documented, public API of the operating system.

The question then transforms: **is there a combination of legitimate syscalls that allows me to write arbitrary bytes to memory and then execute them?**

The answer is yes.

---

## 2. The Linux Memory Model

Each process in Linux operates within its own virtual address space. The kernel maintains a map of memory regions, each with specific permissions:

- **Read (R):** The process can read bytes from that region.
- **Write (W):** The process can modify bytes.
- **Execute (X):** The processor can interpret bytes as instructions and execute them.

These permissions are enforced at the **page** level (4096-byte blocks on x86_64). The hardware enforces these permissions through the NX (No-Execute) bit in page tables. If a program attempts to execute code on a page without X permission, the processor raises an exception and the kernel kills the process with SIGSEGV.

This is the foundation of **DEP** (Data Execution Prevention) and what the community calls **W^X** (Write XOR Execute): the policy that a page should be writable OR executable, but never both at the same time.

The offensive question now becomes more specific: **can I change these permissions after memory has already been allocated?**

---

## 3. The Primitives: mmap and mprotect

### mmap: Requesting Memory from the Kernel

The `mmap` syscall allows a process to request regions of virtual memory. In its simplest form (anonymous mapping), it tells the kernel: "give me N bytes of memory with these permissions." The kernel finds a gap in the process's address space, configures the page tables, and returns the address.

The critical point is that `mmap` accepts a protection argument that defines the region's initial permissions. A program can request memory with read and write permissions (RW), which is completely normal: this is how memory is allocated for data, buffers, and structures.

### mprotect: Changing Permissions at Runtime

Here is the central piece. The `mprotect` syscall allows a process to **modify the permissions of an already-existing memory region**. It takes three arguments: the base address (page-aligned), the size, and the new permissions.

This syscall exists for entirely legitimate reasons:

- **JIT compilers** (V8, LuaJIT, .NET CLR): they generate machine code at runtime, write it to RW memory, and then need to make it executable.
- **Dynamic loaders** (`ld-linux.so`): they load shared libraries and need to adjust permissions for each ELF segment.
- **Garbage collectors**: some implement write barriers by manipulating page permissions.
- **Debuggers**: they need to write breakpoints into executable memory.

The kernel does not distinguish between a JIT compiler and an attacker. Both use the same interface, with the same arguments, in the same way. The syscall has no concept of "intent."

---

## 4. The Technique: Execution Flow

The flow follows a straightforward logic once the primitives are understood:

### Phase 1 — Space Reservation

A page of memory is requested from the kernel with read and write permissions. This operation is indistinguishable from any normal memory allocation: a program calling `malloc` internally ends up doing exactly the same thing. There is nothing anomalous about this request.

### Phase 2 — Payload Writing

With the memory allocated and write-permitted, the payload (x86_64 machine code) is copied to the region. This is a write of bytes to the process's own memory. From the kernel's perspective, it is identical to filling a buffer with network data or copying file contents.

The payload must be **position-independent**: it must work correctly regardless of which virtual address it is loaded at. This is achieved by using instruction-pointer-relative addressing (RIP-relative on x86_64) instead of absolute addresses. The payload cannot assume it will be at a fixed address because `mmap` returns addresses chosen by the kernel, influenced by ASLR.

### Phase 3 — Permission Transition

Here the critical step occurs. `mprotect` is used to change the region's permissions from RW (read/write) to RX (read/execute). After this call:

- Writing is no longer possible (W was removed).
- Execution is now possible (X was added).

The W^X policy is respected at all times: there was never an instant where the page was simultaneously writable and executable. First it was RW (could be written but not executed), now it is RX (can be executed but not written). The kernel allows this transition without objection.

### Phase 4 — Control Transfer

The final step is to divert the execution flow to the address where the payload resides. In low-level terms, this is a `call` or `jmp` to the address returned by `mmap`. The processor begins decoding the bytes at that address as instructions and executes them.

From the processor's perspective, there is no difference between executing instructions that were compiled a year ago and stored on disk, or instructions that were written a microsecond ago. Bytes are bytes.

### Phase 5 — Cleanup

After execution, the memory is freed with `munmap`. The region disappears from the process's memory map. No trace of the allocation remains in the process state once the operation is complete.

---

## 5. Offensive Implications

### Why this technique is relevant

1. **It never touches disk.** The payload exists only in virtual memory. Detection mechanisms based on file scanning (traditional antivirus, file integrity monitoring) see nothing because there is nothing to see on the filesystem.

2. **It requires no elevated privileges.** All syscalls involved are accessible to unprivileged processes. A normal user can execute this entire flow.

3. **It is operationally clean.** It does not modify existing binaries, does not create temporary files, does not alter persistent system state. If the process terminates, the evidence evaporates with it.

4. **It is the foundation for more advanced techniques.** This RW→RX→Execute pattern is the building block for: reflective loading (loading DLLs/SOs from memory), fileless malware (via `memfd_create`), process hollowing, and any form of injection that does not depend on files on disk.

### Combination with other primitives

The technique becomes significantly more powerful when combined with:

- **`memfd_create`:** Creates a file descriptor backed only by memory. Allows executing a complete ELF without it existing as a file on disk. The filesystem records nothing.
- **`ptrace`:** Allows writing to another process's memory and manipulating its registers. Combined with mprotect, it enables injecting and executing code in foreign processes.
- **`process_vm_writev`:** Direct write to another process's address space without requiring full ptrace.

---

## 6. Defensive Perspective

### Detection

Detecting this technique requires operating at layers that the attacker cannot easily evade:

**Syscall monitoring (auditd / seccomp-bpf / eBPF):**
The clearest signal is the sequence `mmap(RW)` followed by `mprotect(RX)` on the same address range, within a process that does not normally perform JIT compilation. This permission transition is the technique's signature. eBPF-based tools can intercept these calls in real time and correlate the arguments.

**Inspection of `/proc/<pid>/maps`:**
Anonymous memory regions (no backing file) with execute permissions are suspicious. Most executable regions in a normal process are backed by files on disk (the binary, libc, etc.). An anonymous executable region warrants investigation.

**Volatile memory analysis:**
If a memory dump of the process is captured while the payload is active, the contents of the executable region can be extracted and analyzed. This requires access to the process before it frees the memory.

### Mitigation

**SELinux / AppArmor:**
Both Mandatory Access Control frameworks can restrict which processes are allowed to use `mprotect` with the PROT_EXEC flag. SELinux's `execmem` policy specifically denies this capability. This is probably the most effective mitigation available.

**seccomp-bpf:**
Allows installing per-process filters that block specific syscalls or argument combinations. A seccomp filter can prohibit `mprotect` with PROT_EXEC for processes that do not need it.

**Kernel hardening (grsecurity/PaX):**
Implementations like PaX MPROTECT enforce strict W^X: a page that was ever writable cannot become executable, period. This eliminates the technique at its root, but breaks compatibility with JIT compilers and other legitimate uses.

**Behavioral monitoring:**
Beyond static rules, modern detection systems (EDR) look for behavioral chains: a process that performs an anonymous mmap, writes high-entropy content, changes permissions to executable, and transfers control, generates a composite alert even if each individual step is benign.

### The defensive paradox

The fundamental difficulty in defending against this technique is that each individual step is a perfectly legitimate operation. Allocating memory is normal. Writing to it is normal. Changing permissions is normal (JIT compilers do it thousands of times per second). Executing code in memory is, literally, what a processor does.

Effective detection cannot be based on blocking individual operations without breaking legitimate functionality. It must be based on **context correlation**: who is doing this, why, and what pattern does the complete sequence follow.

---

## 7. Final Reflection

This technique demonstrates a fundamental principle of offensive security: **the attack surface is not just in bugs**. The system's legitimate interfaces, designed for flexibility and power, are themselves vectors when used with adversarial intent.

The Linux kernel exposes `mprotect` because programs need it. It cannot remove it without breaking a significant portion of the software that depends on it. And it cannot automatically distinguish between a "good" use and a "bad" one because the distinction does not exist at the syscall level: it exists only in the intent of whoever invokes the call.

This tension between functionality and security has no clean solution. Effective mitigations (SELinux, seccomp, PaX) operate by restricting capabilities at the policy level, accepting that certain legitimate programs will need exceptions. Perfect defense would imply a kernel that understands intent, which is, for now, an open problem.

---

*Research conducted as part of the [Black Hat Zig](https://github.com/JorgeBeritan) project — documentation of offensive techniques at the syscall level on Linux.*
