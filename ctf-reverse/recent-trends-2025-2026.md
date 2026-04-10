# Recent Reverse Engineering Trends (2025-2026)

Use this file when the challenge does not look like a normal stripped ELF or PE, or when recent-style CTF reversing patterns show up.

## Table of Contents
- [What changed recently](#what-changed-recently)
- [Modern target triage](#modern-target-triage)
- [Unknown extension / unknown format workflow](#unknown-extension--unknown-format-workflow)
- [Custom VM / bytecode workflow](#custom-vm--bytecode-workflow)
- [Nontraditional rev targets](#nontraditional-rev-targets)
- [Custom metadata, serialized trees, and fake symbol tables](#custom-metadata-serialized-trees-and-fake-symbol-tables)
- [Instrumentation-first patterns](#instrumentation-first-patterns)
- [Recent examples to remember](#recent-examples-to-remember)

## What changed recently

Recent reverse writeups show a broader mix of targets than the old “small stripped ELF flag checker” pattern.

Common modern targets now include:
- custom VM dispatchers paired with separate bytecode blobs
- unknown extensions or custom packed/container formats
- browser extensions, HTML/JavaScript, or other source-like client artifacts
- game logic or nontraditional execution environments such as Minecraft datapacks
- server-style binaries shipped with extra files or remote-only behavior

Treat reverse challenges as “recover the real execution model” rather than “decompile the ELF”.

## Modern target triage

Start with this question tree:

1. **Is it even a native executable?**
   - Run `file`, `binwalk`, `xxd`, `strings`, `zipinfo`, and `7z l`.
   - Check whether the target is really ZIP/APK/XPI/WASM/JS/HTML/data.
2. **Is there an interpreter + bytecode split?**
   - Look for a tiny executable plus a large `*.bin`, `*.dat`, `*.pak`, or resource file.
   - Search for a dispatch loop, jump table, instruction pointer, register array, or `switch(opcode)` pattern.
3. **Is the program serializing or deserializing a custom format?**
   - Look for repeated magic values, node/tree recursion, length-prefixed strings, hashes, or save/load routines.
4. **Is the easiest path dynamic, not static?**
   - Hook compares, dump decoded buffers, instrument register state, or patch final checks.
5. **Is the target really “reverse over source”?**
   - For HTML, JS, extensions, datapacks, and config-heavy targets, read the source and reconstruct the transform directly.

## Unknown extension / unknown format workflow

When the file is not obviously ELF/PE/Mach-O/APK/WASM, do not guess. Classify the container first.

```bash
file sample
binwalk -Me sample
7z l sample
zipinfo sample
xxd -l 128 sample
strings -a -n 4 sample | head -100
```

Checklist:
- look for magic values near offset 0
- identify endianness from counters, lengths, or timestamps
- search for length-prefixed strings and recursive node encodings
- compare write/save code with the provided mystery file instead of reversing the entire reader
- if only a `pack` path works, feed controlled test directories into it and diff the output files to infer the on-disk layout

This is the right mental model for challenges that look like custom filesystems, archive formats, save files, or custom “symbol tables”. In practice, many of these are just application-specific serialized trees, node graphs, or metadata tables with hashes or offsets.

## Custom VM / bytecode workflow

If you see an executable plus a blob, prioritize building a disassembler before deep decompilation.

### Step 1: Recover VM state layout
Identify:
- instruction pointer
- register file
- data pointer / stack pointer
- bytecode buffer
- memory arena / tape / stack
- halting condition and success check

### Step 2: Recover opcodes
For each handler, record:
- opcode value
- operand widths and signedness
- register vs immediate arguments
- whether control flow is absolute or relative
- side effects on flags / condition state

### Step 3: Write a disassembler immediately
A rough disassembler is often enough. You do not need a full decompiler yet.

Suggested output columns:
- byte offset
- raw bytes
- mnemonic
- decoded operands
- comment / inferred semantics

### Step 4: Lift only what matters
Once the instruction set is mapped, either:
- emulate the bytecode
- translate it to Python
- lift it to SSA / Z3 constraints
- or simplify the verifier to recover the expected input

### Step 5: Instrument instead of suffering
Hook the VM loop or individual handlers and log:
- IP
- opcode
- register changes
- memory writes
- branch decisions

This usually beats staring at a 10k-bytecode verifier.

## Nontraditional rev targets

### Browser extensions / XPI / web client bundles
- `.xpi` is usually just a ZIP.
- inspect `manifest.json`, background scripts, content scripts, bundled JS, and embedded keys.
- search for `fetch`, `crypto`, `atob`, base64 strings, and hardcoded secrets.
- do not force the challenge into binary RE if the answer is in source.

### HTML / JavaScript “intro to rev” targets
- read the validation function first
- beautify/minify as needed
- emulate or invert the transform directly in Python/JS
- patching client logic is often faster than line-by-line deobfuscation

### Minecraft datapacks / game logic
- treat command files and data tables as bytecode or DSL
- recover the register/state model
- extract matrices, constants, and update rules into Python
- once the forward transform is known, solve algebraically or by inversion/SMT

### PowerShell / script-heavy rev
- avoid blind execution
- deobfuscate strings and layered decoders first
- rename variables aggressively
- dump intermediate decoded payloads at each stage

### Remote/server style rev
- the provided binary may be a helper, serializer, or protocol endpoint rather than a standalone checker
- inspect companion files, sample requests, or data files first
- replay inputs while tracing read/write boundaries

## Custom metadata, serialized trees, and fake symbol tables

When you say “custom symbolic table”, the most useful interpretation in CTFs is often:
- a homegrown symbol/relocation-like table
- a serialized AST or tree of nodes
- a metadata table describing handlers, offsets, filenames, or hashes
- a section-like container invented by the author

Heuristics:
- repeated 8-byte values often mean offsets, hashes, or child pointers
- `0xffffffffffffffff` or similar sentinels often mark null children or terminators
- duplicated key fields in two structures often link names to contents or metadata to payloads
- save routines are gold: reverse the writer, not the reader
- make tiny synthetic examples and diff the outputs to map fields with certainty

If the layout resembles a symbol table, still ask:
- what does each entry point to?
- are names stored inline or length-prefixed?
- are offsets absolute, relative, or hashed?
- is traversal linear, recursive, or tree-based?

## Instrumentation-first patterns

Recent rev workflows lean harder on instrumentation because many targets are easier to observe than to fully decompile.

Good defaults:
- **Frida** for intercepting compares, dumping decoded strings, logging VM state, and bypassing anti-debug
- **angr / Triton / z3** when a verifier can be lifted into constraints
- **rr / gdb Python / radare2 scripts** for repeated tracing and state snapshots
- **custom Python emulators** for VMs, DSLs, datapacks, and custom binary formats

Prefer “hook and dump the computed truth” when:
- the challenge validates against a final buffer
- decompiler output is noisy but execution is stable
- the target decodes or decrypts data just before comparison

## Recent examples to remember

These are useful pattern reminders, not copy-paste solves.

- **corCTF 2025 `bubble`**: a VM/bytecode reversing challenge where the key move is mapping the instruction set and reasoning about the higher-level abstractions built on top of the VM. The writeup describes a 10k-bytecode verifier with function calls, iteration, and recursion. See CTFtime summary. 
- **scriptCTF 2025 `vm`**: the writeup explicitly recommends reversing the VM, mapping opcodes, and writing a disassembler for the external `check.bin` bytecode rather than only staring at the dispatcher. 
- **LA CTF 2025 `McFlagChecker`**: reversing a Minecraft datapack by extracting the register model and lifting the arithmetic, XOR, exponentiation, and matrix multiplication into a solvable form. 
- **Jeanne d'Hack 2025 `CustomFs`**: a custom filesystem/container challenge where the fastest route is reconstructing the serialized format from the program’s save logic and test outputs. 
- **UMCS CTF 2025 `htpp-server`**: reminder that unknown extensions are now common and should trigger classification first, not assumptions about platform or toolchain. 
- **Jeanne d'Hack 2026 Reverse Intro**: even a single HTML file with a `checkFlag` routine can be a reverse challenge. 
- **picoCTF 2026 `The Add/On Trap`**: a reverse challenge based on a Firefox `.xpi` extension, solved by unpacking it, inspecting `background/main.js`, and using the exposed Fernet key and ciphertext.

## Minimal playbook to add to your muscle memory

When the target is weird:

1. classify the artifact
2. identify the execution model
3. dump or reconstruct the data model
4. instrument before over-decompiling
5. build a tiny parser/disassembler/emulator as soon as the format is stable
6. solve the verifier, not the aesthetics
