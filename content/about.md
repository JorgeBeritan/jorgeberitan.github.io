---
title: "About"
layout: "single"
url: "/about/"
summary: "About me"
ShowToc: false
ShowReadingTime: false
---

## Jorge Beritan

Security engineer focused on offensive security, systems programming, and low-level tooling development.

Currently building [Black Hat Zig](/research/) — a research project exploring Zig as a language for offensive security tooling. The project documents the implementation of techniques ranging from network reconnaissance to process injection, fileless execution, and implant engineering, all built from syscall-level primitives.

### Why Zig

Zig offers a unique combination for offensive tooling that no other language matches:

- **Zero runtime overhead** — no garbage collector, no hidden allocations, no runtime that inflates binaries or leaves signatures
- **Comptime** — compile-time code execution enables obfuscation, API hashing, and string encryption resolved before the binary exists
- **Direct C interop** — call Win32, NT API, or POSIX interfaces without wrappers or bindings
- **Cross-compilation** — target any platform from any platform in a single command

### Contact

- GitHub: [JorgeBeritan](https://github.com/JorgeBeritan)
