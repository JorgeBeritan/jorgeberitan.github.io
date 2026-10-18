---
title: "Fileless Execution on Linux: memfd_create as a Primitive"
date: 2026-10-10
description: "Using memfd_create to execute complete ELF binaries without them ever existing as files on the filesystem."
tags: ["linux", "syscalls", "memfd_create", "fileless", "offensive-security"]
series: ["Linux Offensive Primitives"]
cover:
  image: ""
  alt: ""
  relative: false
ShowToc: true
TocOpen: true
---

**Prerequisite:** [Dynamic Code Execution: mprotect as an Attack Vector](/research/mprotect-ejecucion-dinamica-de-codigo-en-linux/)

---

## Summary

This research documents the use of the `memfd_create` syscall as a primitive for executing complete ELF binaries without them ever existing as files on the filesystem. The technique represents a natural evolution from the dynamic shellcode execution via `mprotect` documented previously: where that technique allows executing fragments of machine code from memory, this one allows executing **complete programs** without leaving a trace on disk. The technical mechanism, its relationship to analogous techniques on Windows, and available detection strategies are analyzed.

---

## 1. The Problem

Code execution via `mprotect` has a practical limitation: the payload is raw shellcode. For complex operations (persistence, lateral movement, exfiltration), complete programs need to be executed, not machine code fragments.

The conventional route for executing a program on Linux is:

1. Write the binary to disk.
2. Call `execve` with the file path.

The problem is obvious: step 1 leaves an artifact on the filesystem. A file on disk can be scanned by antivirus, detected by file integrity monitoring (AIDE, OSSEC, Tripwire), logged by auditd, and recovered in forensic analysis even after deletion.

The question is direct: **is it possible to execute a program without it ever existing as a file on disk?**

---

## 2. The Primitive: memfd_create

### Origin and legitimate purpose

`memfd_create` was introduced in Linux 3.17 (2014). Its original purpose is to create **anonymous memory-backed files**. Unlike a traditional file that resides on a mounted filesystem, a memfd exists solely as a kernel object in RAM.

Legitimate use cases include:

- **Shared memory between processes:** Safer than `/dev/shm` because the fd can be sealed with `F_SEAL` to prevent modifications.
- **Temporary files without collision risk:** No need for a temp directory or a unique name.
- **Containers and sandboxing:** Systems like Docker and Flatpak use them to pass data between isolated processes.

The syscall takes two arguments: a debug name (visible in `/proc/<pid>/fd/`) and optional flags. It returns a file descriptor that behaves like any other fd: it can be read, written, mapped, and — critically — passed to `execveat` for execution.

### The key property

A memfd **has no entry in any filesystem directory**. It does not exist in `/tmp`, does not exist in `/dev/shm`, does not exist on any mount point. The only way to access it is through the file descriptor within the process that created it, or through the virtual entry `/proc/<pid>/fd/<N>` while the process is alive.

If the process terminates and no other process inherited the fd, the memfd disappears completely. There is nothing to recover from disk because it was never on disk.

---

## 3. The Mechanism: From Bytes in Memory to Running Process

### Phase 1 — Container creation

`memfd_create` is invoked to obtain an anonymous fd. The `MFD_CLOEXEC` flag is applied so the fd closes automatically upon `execveat`. This is an operational hygiene measure: if the fd survives the exec, the child process inherits it and an investigator could find it by listing `/proc/<pid>/fd/`.

### Phase 2 — Payload loading

The contents of an ELF binary are written to the memfd using the `write` syscall, exactly as one would write to a normal file. The payload can come from multiple sources: embedded in the loader itself, downloaded from the network, decrypted at runtime, or received through a socket.

What matters is that the write occurs to a kernel memory object, not to a block on a storage device. No disk sector records the operation, no filesystem journal persists it, no page cache is linked to an inode on a physical device.

### Phase 3 — Execution

The `execveat` syscall (number 322 on x86_64) is the modern variant of `execve` that accepts a file descriptor instead of a path. With the `AT_EMPTY_PATH` flag, it tells the kernel: "execute the content referenced by this fd, do not look up any path."

The kernel proceeds exactly as it would with a normal `execve`: verifies the content is a valid ELF, loads segments into memory, configures the stack, and transfers control to the program's entry point. The only difference is that the ELF's backing store is an anonymous memory object instead of a file on a filesystem.

From the kernel's perspective, the operation is completely ordinary. The distinction between "file on disk" and "file in memory" is a question of storage backend, not of operation legitimacy.

---

## 4. Comparison with Analogous Windows Techniques

The Windows ecosystem has techniques with similar goals that are instructive in comparison.

### Process Herpaderping

Exploits the temporal separation between creating a memory section (NtCreateSection) and the security software scanning the file. The file is mapped as a section, then the file content on disk is overwritten with benign data before the AV inspects it. The process executes the original content, but the file on disk shows harmless content.

### Process Ghosting

Similar to Herpaderping but more aggressive: after mapping the section, the file is marked for deletion (delete-pending state) and the handle is closed. The file disappears from the filesystem, but the section remains valid in memory.

### The fundamental difference

Both Herpaderping and Ghosting depend on an architectural quirk of Windows: process creation is a multi-step flow with exploitable intermediate states. The file exists on disk at least briefly — long enough to map it as a section.

`memfd_create` on Linux is conceptually cleaner: **the file never touches disk at any point**. There is no scanning time window because there is no filesystem artifact to scan. No gap between steps is exploited — a primitive designed to operate exclusively in memory is used.

The difference reflects the design philosophies of both systems. Windows offers a complex process creation model with multiple abstraction layers, and complexity generates attack surface in the transitions between layers. Linux offers simple, direct primitives, and the attack surface emerges from the inherent power of those primitives.

---

## 5. Indicators and Detection

### What the defender sees

**In `/proc/<pid>/fd/`:**
While the loader has the memfd open (before `execveat`), the fd appears as a symbolic link to `memfd:<name>`. The name is what was passed to `memfd_create`. After `execveat` with `MFD_CLOEXEC`, the fd disappears.

**In `/proc/<pid>/exe`:**
Here is a strong indicator. Normally, `/proc/<pid>/exe` points to the on-disk binary that was executed (e.g., `/usr/bin/ls`). For a process launched from a memfd, it points to a virtual path like `/memfd:<name> (deleted)`. The presence of "memfd" in this path is a clear signal of fileless execution.

**In auditd logs:**
The `memfd_create` syscall can be logged with an audit rule. The combination of `memfd_create` followed by `execveat` in the same process is highly suspicious and virtually never occurs in normal legitimate use.

### Detection strategies

**Monitoring `/proc/<pid>/exe`:**
Any process whose `exe` link contains "memfd" warrants immediate investigation. EDR tools can periodically scan this path for all active processes. This is the most reliable and hardest-to-evade indicator.

**auditd/eBPF rules:**
Monitor invocations of `memfd_create` (syscall 319) and `execveat` (syscall 322). Correlation of both in the same process, especially if `execveat` uses `AT_EMPTY_PATH`, indicates fileless execution with high probability.

**memfd content analysis:**
While the memfd exists, its contents can be read through `/proc/<pid>/fd/<N>`. An incident responder can capture the payload before the process terminates and the memfd disappears. This requires real-time detection — once the process dies, the evidence is lost.

**seccomp-bpf:**
A seccomp filter can block `memfd_create` for processes that do not need it. Since most programs never use this syscall, the blocking policy has low impact on functionality.

### The race against time

The main difficulty for the defender is temporal. The memfd exists only while the process keeps it open. With `MFD_CLOEXEC`, the fd closes when the payload executes. If the payload process is ephemeral (executes its task and terminates), the window for capturing evidence can be milliseconds.

A sophisticated attacker can shrink this window even further: execute the payload, capture its output via pipes, and terminate the process immediately. By the time a periodic scanner checks `/proc`, the process no longer exists.

---

## 6. Variants and Evolutions

### Loading from the network

In a real operational scenario, the payload would not be embedded in the loader. It would be downloaded at runtime — from a C2 via HTTPS, from a shared resource, or from a DNS tunnel. The bytes travel from the socket directly to the memfd, never touching disk at any point along the way.

### Encryption in transit

The payload can be stored encrypted (in the loader or on the C2 server) and decrypted in memory before being written to the memfd. This adds an additional layer: even if a defender captures the loader, the actual payload is not visible without the decryption key.

### Chaining with ptrace

Instead of executing the payload in the current process, `ptrace` can be used to inject the memfd contents into another already-existing process. This combines fileless execution with process injection: the payload not only does not exist on disk, but executes within the context of a legitimate process.

---

## 7. Final Reflection

`memfd_create` represents an interesting point in the tension between the Linux kernel's functionality and security. It is a useful syscall with clear legitimate use cases, but its ability to create executable objects that never touch disk makes it a first-class offensive primitive.

Unlike Windows techniques that exploit architectural gaps in complex flows, `memfd_create` is a direct tool: it was designed to create files in memory, and that is exactly what an attacker does with it. There is no exploit, no bug, no unexpected behavior. The syscall works perfectly according to its specification.

Detection is possible — `/proc/<pid>/exe` pointing to a memfd is a strong indicator — but complete mitigation requires policy decisions: do we block `memfd_create` for all processes? Only some? How do we handle the legitimate processes that need it?

These questions have no purely technical answers. They are risk management decisions that each organization must make based on their attack surface, their tolerance for operational impact, and the maturity of their security program.

---

*Research conducted as part of the [Black Hat Zig](https://github.com/JorgeBeritan) project — documentation of offensive techniques at the syscall level on Linux.*
