# Frida-Patcher

`fridapatch.py` — harden a stock `frida-server` binary against in-APK anti-Frida
detection. Every patch is **length-preserving**: no ELF offset ever moves, so the
binary stays valid without relocating a single header.

## What it does

Takes a stock `frida-server` release binary (optionally still `.xz`) and:

- Rewrites every string an app can fingerprint (agent filename, temp dir, thread
  names, in-memory markers, injector socket name, …) using replacements that
  preserve **length and character class** — identifiers stay identifiers,
  filenames stay filenames.
- Renames the bare `frida` **prgname** too, so the runtime-assembled `pool-frida`
  worker thread (`GLib pool-%s`) no longer appears in the target — the one
  thread-name that isn't a literal in the binary.
- Optionally moves the hardcoded default port in `.text` (`--patch-port`), or
  leaves it and relies on the runtime `-l` flag.
- Runs a verification pass (size unchanged, ELF still parses, no residual tokens)
  and prints the exact commands to push and drive the patched server.

## Usage

```bash
# Default safe patch, output named "sysmon"
./fridapatch.py frida-server-16.1.10-android-arm64.xz -o sysmon

# Download the stock server for a version + arch, then patch it
./fridapatch.py --fetch 16.6.1 --arch x86_64 -o sysmon --patch-port

# Scan and report only, write nothing
./fridapatch.py frida-server-16.1.10-android-arm64 --check

# Print the anti-Frida detection catalog and exit
./fridapatch.py --list-detections

# Reproducible build + rewrite hardcoded port + push over adb
./fridapatch.py fs -o sysmon -s 1337 --patch-port --push
```

Run `chmod +x fridapatch.py` first if you want to invoke it directly.

## Recommended flags

For almost every engagement, this is the combination you want — maximum
de-fingerprinting with **zero** breakage to spawn or your scripts:

```bash
# from a local file
./fridapatch.py frida-server-16.6.1-android-x86_64.xz \
    -o sysmon -s 1337 -p 41337 --patch-port --patch-signatures

# or let it download the matching build (version must equal your host frida-tools)
./fridapatch.py --fetch 16.6.1 --arch x86_64 \
    -o sysmon -s 1337 -p 41337 --patch-port --patch-signatures
```

Why these:

| Flag | Why it's recommended |
|------|----------------------|
| *(default `safe` tier)* | always on — renames the agent filename, temp dir, thread names (incl. the `pool-frida` prgname), injector socket, etc. This is what beats `proc-maps-scan`, `thread-name-scan`, `file-artifact-scan`, `process-scan`, `unix-socket-scan`. |
| `--patch-signatures` | safe — strips the in-memory agent markers (`FridaScriptEngine`, `GumScript`, `frida-gum`, `frida/runtime/`). Never crosses the wire, so nothing breaks. |
| `--patch-port` | safe — moves the hardcoded `27042`/`27043` off the default (opcode-anchored, per-arch). Beats `default-port-probe` with no `-l` needed. |
| `-s <seed>` | reproducible build (same input + seed = same output). |
| `-p <port>` | pin the control port (5 digits, `10000-65534`); omit for a random one. |
| `-n <name>` | on-device filename to push as (default `sysmon`); also helps `process-scan`. |

**Do NOT use unless you know exactly why:**

| Flag | Reason to avoid |
|------|-----------------|
| `--patch-rpc` | **hangs `-f` spawn** unless you also patch the host `frida/core.py` to the same tag (see the ⚠️ note under *Patch tiers*). |
| `--aggressive` | rewrites bare `frida` → breaks `frida.Error.*` and the Frida JS global your scripts call. |

> `--patch-agent-symbol` was **removed** — renaming the agent's exported symbol
> can't be done by binary patching (needs a source rebuild). See the note under
> *Patch tiers*.

If a target still detects Frida after this, it's using a **runtime/behavioural**
check (anon exec pages, D-Bus port-sweep, ptrace, inline-hook/CRC) — those need a
Frida-side hook, not a server patch. Run `--list-detections` for the full map.

## Fetching the server (`--fetch`)

Instead of a local file you can have the tool download the stock server straight
from GitHub releases — you name the version and the arch (no auto-detection):

```bash
./fridapatch.py --fetch <version> --arch <arm|arm64|x86|x86_64> [patch flags...]
```

- `--fetch <version>` — a frida release tag, e.g. `16.6.1`. **Match your host's
  `frida` / `frida-tools` version**: a frida-server only talks to a client of the
  same version.
- `--arch` — one of `arm`, `arm64`, `x86`, `x86_64` (the four android
  frida-server builds; `arm` = 32-bit armeabi-v7a, `arm64` = aarch64). Required
  with `--fetch`.

The download is verified to actually be an ELF of the requested arch before
patching. Uses only the Python standard library (`urllib`) — no extra installs.

## Patch tiers

| Flag | Tier | Rewrites | Risk |
|------|------|----------|------|
| *(default)* | `safe` | `re.frida.server`, `frida-agent`, `frida-helper`, thread names (`gmain`, `gdbus`, `gum-js-loop`, `pool-frida`, `pool-spawner`, `frida-main-loop`, `frida-eternal-agent`, `frida-generate-certificate`), `linjector`, `LIBFRIDA`/`libfrida` | none — cosmetic or consistently-renamed paths |
| `--patch-signatures` | `signature` | `FridaScriptEngine`, `GumScript`, `GumInterceptor`, `frida/runtime/`, `frida-gum` (in-memory scan markers, agent-side) | none — never crosses the wire |
| `--patch-rpc` | `rpc` | `frida:rpc` | **hangs spawn** unless the host client is patched too — see below |
| `--aggressive` | all + `frida` | bare `frida` leftovers | **expect breakage** — hits `frida.Error.*` and the JS global |

> **⚠️ `--patch-rpc` — read before using.** `frida:rpc` is the message tag the
> **host frida client** and the **injected agent** must both use. This tool only
> patches the server/agent, so after `--patch-rpc` the agent listens for a
> renamed tag while your host `frida` / `frida-ps` still sends `frida:rpc`. The
> RPC channel never completes: `frida-ps` may work, but **`-f` spawn hangs at
> "Spawning …" with the app frozen** (frida spawns suspended and never resumes).
>
> To actually use it you must **also patch the host client to the same tag**. On
> the host that string lives in editable Python — `frida/core.py` (2
> occurrences) — so rename both to the *exact* replacement the patch chose (use
> `--seed` for a reproducible tag, then read it from the run output). It is
> length/`:`-preserving, e.g. `frida:rpc` → `xxxxx:xxx`. You must redo this on
> every re-patch (new seed = new tag) and on every `frida-tools` upgrade, on
> every host that connects. For almost every engagement this isn't worth it —
> **leave `--patch-rpc` off.** If a target truly memory-scans for `frida:rpc`,
> defeat it with a runtime hook that filters the memory read instead.

> The agent's exported symbol `frida_agent_main` (and `gum_*`), plus its
> `DT_SONAME` `libfrida-agent-raw.so`, are **not** renameable by binary patching
> — they live in the agent's protected dynamic tables, so changing them needs the
> GNU hash rebuilt, which only a source rebuild can do. To beat
> `module-export-scan`, use a from-source anti-detection build
> ([strongR-frida-server](https://github.com/hzzheyang/strongR-frida-server) or
> [phantom-frida](https://github.com/TheQmaks/phantom-frida)), or hook the app's
> `dl_iterate_phdr` / `dlopen` enumeration at runtime.

> The default `safe` tier also renames the bare `frida` **prgname**. GLib formats
> it into `pool-%s`, so a `pool-frida` worker thread shows up in the *target* even
> though `pool-frida` is never a literal in the binary. The rename is null-bounded
> (`\0frida\0`) so `libfrida` / `re.frida.server` stay untouched. Validated
> on-device (Android 14, arm64): after patching, no `gmain`/`gdbus`/`gum-js-loop`/
> `pool-frida`/`pool-spawner` thread remains in the injected process.

## Key options

| Option | Purpose |
|--------|---------|
| `-o, --output` | output path (default `<input>-patched`) |
| `-n, --name` | on-device filename to push as (default `sysmon`) |
| `-p, --port` | control port, 10000–65534 (default random) |
| `-s, --seed` | RNG seed for a reproducible build |
| `--patch-port` | rewrite the hardcoded default port in `.text` |
| `--keep TOKEN` | leave a token untouched (repeatable) |
| `--max-port-sites` | refuse `--patch-port` above N hits (default 16) |
| `--force` | proceed past the port-site safety limit |
| `--check` | scan/report only, write nothing |
| `--list-detections` | print the anti-Frida check catalog |
| `--push` | `adb push` the result and `chmod` it |

## Design guarantees

- **Length-preserving** — every replacement is the exact byte length of the
  original; no offsets move.
- **Character-class-preserving** — lower→lower, upper→upper, digit→digit,
  separators kept; replacements never re-introduce `frida`/`gum`.
- **Consistent** — patterns are applied longest-first against the already-mutated
  buffer, and each functional token maps to one fixed replacement everywhere, so
  the write-path and load-path strings stay in sync.
- **Agent-safe** — the string rewriter never touches a symbol/hash/reloc/code
  region (see below), so the embedded agents keep loading.

## Embedded-agent protection (why spawn keeps working)

`frida-server` embeds **one `frida-agent` .so per architecture** (x86_64 / x86 /
arm64 / arm), and on spawn it writes the target-arch agent to disk and injects
it. Those agents contain the same fingerprint strings we rename — including in
their **`.dynstr`**. Renaming a symbol name in an agent's `.dynstr` *without
rebuilding its `.gnu.hash`* breaks that agent's symbol resolution at load time.
The tell-tale symptom is: **`frida-ps` works but `-f` dies with
`bootstrapper crashed with signal 11`** — because the agent is only mapped into
the target during **spawn**.

To prevent this the patcher parses every embedded ELF and carves out a set of
**protected ranges** — `.dynstr`, `.dynsym`, `.gnu.hash`/`.hash`, `.rela*`,
`.plt`/`.got`, `.init`/`.fini`, and all executable (`SHF_EXECINSTR`) sections, in
the main binary *and* each agent — then skips any string hit that lands inside
one (shown as the `skip` column). Because the agents physically live *inside* the
main binary's ~100 MB `.text`, each agent's **`.rodata`/`.data`** is explicitly
re-opened so the thread-name literals the *target* reads (`gmain`, `gdbus`,
`gum-js-loop`) and the in-memory sourcemaps still get renamed. Net result: every
agent's code and symbol tables stay **byte-identical to stock** (spawn works)
while its observable strings are de-fingerprinted.

## Arch-aware port patching (`--patch-port`)

The port rewrite is **opcode-anchored per architecture**, detected from the ELF
header (`arm64` / `arm` / `x86` / `x86_64`):

- **ARM64** — matches the specific `movz`/`movk w|x` opcode at 4-byte alignment.
- **ARM** — matches both the **Thumb-2 `MOVW`** (T3 encoding, the usual
  armeabi-v7a build) and the A32 `MOVW rd` encoding.
- **x86 / x86_64** — matches `mov r32, imm32` (`B8+rd`, incl. `REX.B` for
  `r8d–r15d`) and rewrites **only the 4 immediate bytes**, keeping the opcode.

Because it anchors on the opcode, it will **never** overwrite a data word or an
unrelated instruction whose operand merely equals the port — e.g. a `call rel32`
whose displacement happens to be `0x69a2`. (A naive bare-value scan on x86 would
corrupt exactly those, breaking call targets.) Anything on an unrecognised arch
skips immediate patching entirely and relies on the runtime `-l` flag.

The immediate scan runs over the **main server's own code only** — every
embedded per-arch agent is carved out of the range first, so a port-valued
constant *inside an agent* can never be mistaken for the listener port and
corrupted (which would break spawn). The tool drops the `-l` flag from the start
command **only when it actually rewrote a control-port immediate**; if it finds
just the ASCII/help copy of the port (or nothing on that arch), it keeps `-l` so
the server still lands on the right port.

## What it can NOT fix (needs a Frida-side hook)

`port-sweep` · `anon-exec-mappings` · `module-export-scan` · `tracer-pid` ·
`inline-hook-check` · `code-integrity-crc` · `exec-page-perms` ·
`named-pipe-fd-scan` · `timing-hook-check` ·
`java-layer-gates` (RootBeer / jail-monkey / DexGuard / Play Integrity).

These are behavioral, not string-based — patching the server binary cannot help.
Run `--list-detections` for the full catalog and per-check mitigation notes.

## Driving the patched server

```bash
# stage
adb push sysmon /data/local/tmp/sysmon
adb shell "su -c 'chmod 755 /data/local/tmp/sysmon'"

# start (moved port via -l, or compiled-in via --patch-port)
adb shell "su -c '/data/local/tmp/sysmon -l 127.0.0.1:<PORT> -D'"

# forward + drive — USB mode (-U) probes the default port only, so use -H
adb forward tcp:<PORT> tcp:<PORT>
frida-ps -H 127.0.0.1:<PORT>
frida -H 127.0.0.1:<PORT> -f com.example.app -l bypass.js --no-pause
```

> `-U` / `frida-ps -U` will **not** see this server — always connect with
> `-H 127.0.0.1:<PORT>`.

## Changelog

### 2026-11-15 (correctness + ARM/agent hardening)

- **`--patch-port` no longer over-promises.** The `-l` flag is dropped from the
  start command **only when a control-port instruction immediate was actually
  rewritten** — previously an ASCII/help-text hit (or a cluster-only hit) could
  make the tool claim "port compiled in" while the server still bound the
  default port. A warning now fires when only non-functional copies were found.
- **Port immediates are scanned in main-server code only.** The embedded
  per-arch agents are carved out of the scan range, so a port-valued constant
  inside an agent can no longer be mis-patched and break spawn. Verified by
  byte-diff: a full `--patch-port --patch-signatures` run changes **zero** bytes
  in any agent's protected sections, and the only `.text` edits are the port
  immediates (opcode preserved).
- **ARM `--patch-port` now covers Thumb-2.** Emits both the Thumb-2 `MOVW` (T3)
  and A32 encodings — armeabi-v7a frida-server is normally Thumb-2, which the
  old A32-only matcher missed.
- **`gmain` / `gdbus` thread names are null-bounded** (`gmain\0` / `gdbus\0`) so
  they can't corrupt a longer string that merely begins with them.
- **Honest detection-coverage report.** Each vector is scored against the
  specific indicator tokens actually present in the build; a token left intact
  shows `partial (n/m) - enable <flag>` instead of a blanket "covered".
- **`--check` returns a real exit code** (non-zero when verification fails),
  seed-reproducible builds no longer depend on whether `-p` was passed, and
  `--push` shell-quotes the device path.

### 2026-08-11 (detection coverage)

- **New thread-name literals rewritten in the `safe` tier**: `frida-main-loop`,
  `frida-eternal-agent`, `frida-generate-certificate`. These are real 16.x
  thread/GSource names that a `/proc/self/task/*/comm` scan (or in-memory scan)
  still catches after the old patch — the long ones truncate to `frida-eternal-a`
  / `frida-generate-` in `comm` but still start with `frida`. Closes a gap in the
  already-"covered" `thread-name-scan` vector.
- **`GumInterceptor` added to `--patch-signatures`** alongside `GumScript` — an
  in-memory Gum marker that never crosses the wire.
- **`--list-detections` catalog expanded** with four runtime/behavioural vectors
  that binary patching can't fix (documented with the right Frida-side mitigation):
  `code-integrity-crc`, `exec-page-perms`, `named-pipe-fd-scan`, `timing-hook-check`.
- **`module-export-scan` note updated** to include the `libfrida-agent-raw.so`
  `DT_SONAME` and point at source-rebuild servers (strongR-frida / phantom-frida).

### 2026-08-11

- **`--patch-port` no longer prints a redundant `-l`.** When the default port is
  compiled into the binary the start command is just `<name> -D`; an inline
  fallback (`-l 127.0.0.1:<port>`) is shown in case a build encodes the default
  in a form the opcode-anchored rewrite doesn't catch. Without `--patch-port`,
  `-l 127.0.0.1:<port>` is still printed as the authoritative way to move the
  listener.
- **Warn when `-p/--port` is a Frida default (`27042`/`27043`)** — that made
  `--patch-port` a silent no-op and left the default-port probe firing.
- **`-p/--port` help text corrected to `10000-65534`** (was `10000-65535`; the
  upper bound is 65534 so the ASCII literal stays 5 digits).
- Dropped the trailing "Still uncovered … / Run `--list-detections`" footer from
  the driving-commands output. The catalog still prints via `--list-detections`.
