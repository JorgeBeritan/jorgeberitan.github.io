---
title: "Planning: Fileless Implant for Linux"
date: 2026-10-14
description: "Architecture and design of a fileless implant with migration capability using exclusively direct syscalls in Zig."
tags: ["linux", "syscalls", "implant", "fileless", "zig", "offensive-security", "architecture"]
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

## 1. Motivation

Throughout this series, four techniques were implemented in isolation: direct syscalls, memory inspection via `/proc`, dynamic execution with `mprotect`, fileless execution with `memfd_create`, and process injection with `ptrace`. Each demonstrated an individual capability.

This planning document answers a natural question: **what happens when these primitives are composed into a single tool?**

The result is an implant — a program that maintains persistent access to a system, executes commands, and resists detection. Not as a theoretical concept: as functional code where every component uses exclusively the primitives already implemented and documented.

---

## 2. Design Principles

### 2.1 Zero libc dependency

The implant never invokes libc functions. Every operation goes through direct syscalls using `std.os.linux.syscallN`. The purpose is concretely operational:

- **LD_PRELOAD cannot intercept it.** A defender hooking `write()`, `connect()`, or `execve()` via LD_PRELOAD sees nothing because the implant never calls those libc functions. It calls the kernel directly.
- **libc-based tracing tools do not detect it.** `ltrace` instruments calls to shared libraries. If there are no shared library calls, `ltrace` reports nothing.
- **Reduced detection surface.** Fewer dependencies means fewer points where an EDR can insert hooks.

### 2.2 No disk presence

The implant binary never exists as a file on the filesystem. It is loaded and executed exclusively through `memfd_create` + `execve` via `/proc/self/fd/N`. The only persistent presence is in process memory.

### 2.3 Migration capability

The implant can transfer its execution to another process via `ptrace`. This means that even if the original process that loaded it is terminated, the implant can continue operating inside a legitimate system process.

### 2.4 Direct communication

The C2 connection is established using direct socket syscalls (`socket`, `connect`, `read`, `write`). Zig's stdlib network layer is not used.

---

## 3. Architecture

The system is composed of three independent pieces:

### 3.1 Loader (dropper)

**Responsibility:** Load the implant into memory and execute it without touching disk.

**Flow:**
1. Contains the implant binary embedded at compile time (`@embedFile`)
2. Creates a memfd with `memfd_create`
3. Writes the implant ELF to the memfd
4. Executes via `execve("/proc/self/fd/N")`
5. The loader process is completely replaced by the implant

**Key characteristic:** After `execve`, the loader ceases to exist. The running process IS the implant, but loaded from memory. If an investigator lists processes, they see a process with no associated binary on disk.

### 3.2 Implant (core)

**Responsibility:** Maintain C2 communication, execute commands, and persist on the system.

**Capabilities:**

| Command | What it does | Syscalls involved |
|---|---|---|
| `info` | Reports PID, UID, hostname, working directory | `getpid`, `getuid`, `uname`, `getcwd` |
| `exec <cmd>` | Executes a command and returns output | `fork`, `execve`, `pipe`, `read`, `wait4` |
| `maps` | Reads and sends `/proc/self/maps` of the current process | `openat`, `read`, `close` |
| `migrate <pid>` | Injects the implant into another process via ptrace | `ptrace`, `wait4` |
| `exit` | Closes the connection and terminates cleanly | `close`, `exit` |

**Main execution flow:**
1. Establishes a reverse TCP connection to the C2 (`socket` → `connect`)
2. Enters a command reception loop
3. Parses each received command
4. Executes the corresponding operation
5. Sends the result to the C2 over the same socket
6. Repeats until `exit` is received

### 3.3 C2 Listener

**Responsibility:** Receive the implant's connection and provide a command interface.

**Implementation:** For the first version, `netcat` (`nc -lvp <port>`) is sufficient. The protocol is plaintext over TCP. In a later version, a dedicated C2 in Zig can be implemented with support for multiple sessions, encryption, and a binary protocol.

---

## 4. Offensive Perspective

### Operational advantages

**Disk invisibility:** Signature-based antivirus scans files on the filesystem. If there is no file, there is no signature to match. The implant exists only in memory, where most traditional AVs do not look.

**Userspace hook evasion:** Monitoring tools operating at the libc level (LD_PRELOAD hooks, library interposition) do not see the implant's operations. Only `strace` (which uses ptrace on the process) or kernel-level instrumentation (eBPF, kprobes) can observe the direct syscalls.

**Process migration:** If the original process is suspicious or about to be terminated, the implant can migrate to a system process (`sshd`, `cron`, `apache2`). After migration, network activity and command execution are attributed to the legitimate process, not the implant.

**Low footprint:** An implant written in Zig with `ReleaseSmall` and no network stdlib weighs a few kilobytes. Fewer bytes in memory means lower probability of detection by memory scanning.

### Limitations

**strace sees everything.** An administrator running `strace -p <pid>` on the implant's process sees every syscall in real time. There is no way to avoid this from userspace without a kernel-level rootkit.

**eBPF sees everything.** eBPF probes execute inside the kernel. It does not matter whether the implant uses libc or direct syscalls — the kernel sees both. A system with good eBPF telemetry detects the activity.

**`/proc/<pid>/exe` betrays it.** The symbolic link points to `memfd:name` or shows `(deleted)`. This is a solid forensic indicator of fileless execution.

**The network connection is visible.** `ss` and `netstat` show the established TCP connection. Traffic can be captured with `tcpdump`. Without encryption and without tunneling, command contents travel in plaintext.

---

## 5. Defensive Perspective

### Indicators of compromise

| Indicator | Where to look | Reliability |
|---|---|---|
| `/proc/<pid>/exe` points to `memfd:*` | Periodic scan of `/proc/*/exe` | High |
| Outbound TCP connection to unusual IP/port | `ss -tnp`, firewall logs | Medium |
| Process without `libc` in maps but with network activity | `/proc/<pid>/maps` | Medium-high |
| `ptrace` ATTACH from non-debugger process | auditd, eBPF hooks on syscall 101 | High |
| `fork`+`execve` from process that normally does not execute | Behavioral monitoring | Medium |

### Proposed detection rules

**auditd:**
- Monitor `memfd_create` (syscall 319) — any invocation warrants logging
- Monitor `execveat` (syscall 322) and `execve` where the path contains `/proc/self/fd/`
- Monitor `ptrace` ATTACH (syscall 101, first arg = 16) from non-debugger processes

**eBPF:**
- Tracepoint on `sys_enter_memfd_create` → log process and memfd name
- Tracepoint on `sys_enter_execve` → alert if path matches `/proc/*/fd/*` or `/memfd:*`
- Correlate: if the same PID performs `memfd_create` followed by `execve` with an fd path, it is fileless execution with high probability

**Periodic scanning:**
- Walk `/proc/*/exe` looking for entries containing "memfd" or "(deleted)" without a corresponding binary on disk
- Compare `/proc/<pid>/maps` with expected libraries for that process type

### Mitigation

- **seccomp-bpf:** Block `memfd_create` and `ptrace` for processes that do not need them
- **Yama ptrace_scope = 2 or 3:** Restrict ptrace to CAP_SYS_PTRACE or disable it entirely
- **SELinux/AppArmor:** Policies restricting execution from memfd and tracing between processes
- **Network segmentation:** Detect and block unauthorized outbound connections at the perimeter firewall

---

## 6. Incremental Development Plan

### Phase 1 — Implant core (connection + basic commands)
- Reverse TCP socket via direct syscalls
- `info` command (PID, UID, hostname)
- `exec` command (fork + execve + output capture)
- Test with `netcat` as C2

### Phase 2 — Reconnaissance
- `maps` command (read /proc/self/maps and send it)
- `ls` / `pwd` via direct syscalls

### Phase 3 — Fileless delivery
- Compile the implant as a separate binary
- Implement the loader with `memfd_create`
- Integrate and test the complete flow: loader → memfd → implant running

### Phase 4 — Migration
- `migrate <pid>` command using ptrace injection
- Save and restore victim process state
- Verify the victim continues executing normally post-migration

### Phase 5 — Integration and hardening
- Test all flows end-to-end
- Optimize binary size (`ReleaseSmall`)

---

## 7. File Structure

```
05-fileless-implant/
├── implant/
│   ├── build.zig
│   └── src/
│       └── main.zig          # Implant core
├── loader/
│   ├── build.zig
│   └── src/
│       └── main.zig          # Loader with memfd_create
└── c2/
    ├── build.zig
    └── src/
        └── main.zig          # Listener (later phase)
```

---

*Planning document for the [Black Hat Zig](https://github.com/JorgeBeritan) project — implementation of offensive techniques at the syscall level on Linux.*
