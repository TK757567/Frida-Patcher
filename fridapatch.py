#!/usr/bin/env python3
"""
fridapatch.py - harden a frida-server binary against in-APK anti-Frida checks.

Takes a stock frida-server release binary (optionally still .xz), rewrites every
string an app can fingerprint, optionally moves the hardcoded default port, and
prints the exact commands to push and drive it.

All patches are LENGTH-PRESERVING: no offset in the ELF ever moves, so the binary
stays valid without relocating a single header. Every occurrence of a given token
is rewritten to the same replacement, which is what keeps the functional strings
(agent filename, temp dir, agent entrypoint symbol) internally consistent.

  ./fridapatch.py frida-server-16.1.10-android-arm64.xz -o sysmon
  ./fridapatch.py --fetch 16.6.1 --arch x86_64 -o sysmon --patch-port
  ./fridapatch.py --fetch 16.1.10 --arch arm64 --patch-signatures
  ./fridapatch.py fs --check
  ./fridapatch.py fs --list-detections

Supported --arch values: arm, arm64, x86, x86_64 (the android frida-server set).
"""

from __future__ import annotations

import argparse
import bisect
import hashlib
import lzma
import os
import random
import shlex
import shutil
import string
import struct
import subprocess
import sys
import urllib.error
import urllib.request

# --------------------------------------------------------------------------
# Catalog of anti-Frida checks seen in the wild, and what actually mitigates
# each one. "binary" = this script fixes it. "runtime" = needs a Frida-side
# hook; no amount of patching the server helps.
# --------------------------------------------------------------------------

DETECTIONS = [
    dict(id="default-port-probe", fix="binary",
         what="connect() to 127.0.0.1:27042 / :27043",
         how="TCP connect with a short timeout; a successful connect == Frida",
         note="Killed by --port (runtime -l flag) or --patch-port (hardcoded default)."),
    dict(id="port-sweep", fix="runtime",
         what="sweep every listening port, D-Bus handshake on each",
         how="reads /proc/net/tcp, connects, sends \\x00AUTH\\r\\n, matches the "
             "D-Bus REJECTED/OK reply that frida-server speaks",
         note="Moving the port does not help. Hook the app's socket/connect or "
              "use frida-gadget over a unix socket instead."),
    dict(id="proc-maps-scan", fix="binary",
         what="/proc/self/maps contains frida / frida-agent / gum-js / gadget / "
              "linjector / re.frida.server",
         how="the injected agent is mmap'd from a file path holding those names",
         note="Fixed: the agent filename and its temp dir are both renamed."),
    dict(id="anon-exec-mappings", fix="runtime",
         what="counts anonymous r-xp / rwxp regions in /proc/self/maps",
         how="Gum's code allocator (Interceptor trampolines, Stalker) needs "
             "anonymous executable pages; stock apps have almost none",
         note="Not a string. Hook the maps read, or minimise hook count."),
    dict(id="thread-name-scan", fix="binary",
         what="/proc/self/task/*/comm == gmain / gdbus / gum-js-loop / "
              "pool-frida / pool-spawner / frida-main-loop / frida-eternal-agent "
              "(comm 'frida-eternal-a') / frida-generate-certificate "
              "(comm 'frida-generate-')",
         how="glib and gum name their worker threads via pthread_setname_np; long "
             "names are truncated to 15 chars in comm but still start with 'frida'",
         note="Fixed: gmain/gdbus/gum-js-loop/pool-spawner plus the frida-main-loop/"
              "frida-eternal-agent/frida-generate-certificate names are rewritten, "
              "and the bare 'frida' prgname that GLib formats into 'pool-%s' is "
              "renamed too, so the pool-frida worker no longer appears."),
    dict(id="process-scan", fix="binary",
         what="walk /proc/*/cmdline and /proc/*/comm for frida-server, "
              "frida-helper, frida-inject, linjector",
         how="ps-equivalent over procfs, or Runtime.exec(\"ps\")",
         note="Fixed by the string rewrite PLUS pushing under a neutral filename "
              "(--name), since comm is derived from argv[0]."),
    dict(id="memory-signature-scan", fix="binary",
         what="scan mapped ranges for LIBFRIDA / frida:rpc / FridaScriptEngine / "
              "the frida-gum and frida/runtime/ sourcemap paths in the agent",
         how="reads maps, then memcmp/strstr over each readable range",
         note="LIBFRIDA and libfrida fixed by default. FridaScriptEngine, "
              "GumScript and the JS sourcemap paths need --patch-signatures. "
              "frida:rpc needs --patch-rpc (it breaks rpc.exports)."),
    dict(id="module-export-scan", fix="runtime",
         what="dl_iterate_phdr + walk .dynsym / DT_SONAME of each module for "
              "frida_agent_main, gum_* exports, or the libfrida-agent-raw.so soname",
         how="manual ELF parse of loaded objects; survives a filename rename",
         note="Binary patching cannot help: the exported symbol AND the DT_SONAME "
              "(libfrida-agent-raw.so) live in the agent's protected dynamic tables "
              "- renaming them means rebuilding its GNU hash, which only a source "
              "rebuild does (strongR-frida-server / phantom-frida). Otherwise hook "
              "the app's dl_iterate_phdr / dlopen enumeration at runtime."),
    dict(id="file-artifact-scan", fix="binary",
         what="access()/stat() on /data/local/tmp/frida-server, "
              "/data/local/tmp/re.frida.server, .../frida-agent-64.so",
         how="cheap filesystem probe, runs even before the port check",
         note="Fixed by the rename of re.frida.server + the --name you push as."),
    dict(id="unix-socket-scan", fix="binary",
         what="/proc/net/unix contains linjector / frida",
         how="the spawn-gating injector opens an abstract unix socket",
         note="Fixed: linjector is rewritten."),
    dict(id="tracer-pid", fix="runtime",
         what="/proc/self/status TracerPid != 0, or the app self-ptraces",
         how="frida spawn-mode attaches with ptrace during early injection",
         note="Attach to an already-running process instead of -f, or hook the "
              "status read. Not a property of the server binary."),
    dict(id="inline-hook-check", fix="runtime",
         what="CRC / first-16-bytes check of libc, libart and JNI entrypoints",
         how="looks for the b/ldr x16;br x16 trampoline Interceptor writes",
         note="Hook the verifier itself, or replace Interceptor hooks with "
              "Stalker / breakpoint-free strategies."),
    dict(id="code-integrity-crc", fix="runtime",
         what="checksum a native lib / libc .text on disk and compare with the "
              "same range mapped in memory; any inline hook diverges",
         how="reads the file + /proc/self/mem (or the mapped copy) and memcmp's; "
              "a superset of inline-hook-check that catches hooks anywhere in .text",
         note="Not a string. Same mitigation as inline-hook-check: hook the "
              "verifier, or use Stalker / non-patching hook strategies so .text "
              "stays byte-identical to disk."),
    dict(id="exec-page-perms", fix="runtime",
         what="/proc/self/maps shows a NAMED native lib's .text as rwxp "
              "(writable+executable)",
         how="Interceptor mprotect's the target page rw- to write its trampoline; "
             "a stock lib .text is r-xp, so rwxp on a named module is a tell",
         note="Distinct from anon-exec-mappings (which counts ANONYMOUS exec "
              "pages). Not a string - hook the maps read, or restore page perms "
              "to r-xp after installing the hook."),
    dict(id="named-pipe-fd-scan", fix="runtime",
         what="/proc/self/fd symlinks resolve to frida agent<->server pipes or "
              "the injector's abstract unix socket",
         how="readlink() every /proc/self/fd/* looking for pipe:/socket targets "
             "tied to the injection channel",
         note="The abstract-socket name is de-fingerprinted via linjector (see "
              "unix-socket-scan), but anonymous pipe:[inode] fds carry no name - "
              "that part is runtime-only: hook readdir/readlink on /proc/self/fd."),
    dict(id="timing-hook-check", fix="runtime",
         what="measure wall-clock latency of a hooked function or a syscall and "
              "compare against a known-fast baseline",
         how="Interceptor trampolines and especially Stalker add measurable "
             "overhead; a function that suddenly takes N times longer implies a hook",
         note="Not a string. Minimise hook count, avoid Stalker on hot paths, or "
              "hook the clock source (clock_gettime / System.nanoTime) the check "
              "reads so the delta disappears."),
    dict(id="java-layer-gates", fix="runtime",
         what="RootBeer, jail-monkey, DexGuard, SafetyNet/Play Integrity",
         how="Java-side checks that gate the app before any native probe",
         note="Pure Frida-script territory - chain the Java-side hooks at "
              "runtime (jail-monkey -> RootBeer -> any native libtoolChecker.so)."),
]

# --------------------------------------------------------------------------
# Fingerprintable tokens inside frida-server. Tiers:
#   safe       - rewritten by default; cosmetic, or a path/filename that is
#                renamed consistently everywhere it appears
#   signature  - --patch-signatures; in-process memory-scan markers that do not
#                cross the wire to the client
#   rpc        - --patch-rpc; breaks script.exports / rpc.exports
#   aggressive - --aggressive; catches leftovers, real chance of breakage
# `functional` marks a token the binary resolves at runtime, so every occurrence
# must map to the same replacement (the patcher guarantees this).
# --------------------------------------------------------------------------

PATTERNS = [
    (b"re.frida.server", "safe", True, "agent/helper temp dir under /data/local/tmp"),
    (b"frida-gadget", "safe", False, "gadget identity string"),
    (b"frida-portal", "safe", False, "portal binary name"),
    (b"frida-server", "safe", False, "server identity / usage text"),
    (b"frida-helper", "safe", True, "helper binary name (32/64 variants)"),
    (b"frida-inject", "safe", False, "injector binary name"),
    (b"pool-spawner", "safe", False, "thread name"),
    (b"gum-js-loop", "safe", False, "thread name (JS runtime loop)"),
    (b"frida-agent", "safe", True, "agent .so filename (covers -32/-64 variants)"),
    (b"pool-frida", "safe", False, "thread name"),
    (b"linjector", "safe", True, "injector unix socket / helper name"),
    (b"LIBFRIDA", "safe", False, "in-memory marker string"),
    (b"libfrida", "safe", False, "in-memory marker string (lowercase variant)"),
    (b"gmain\x00", "safe", False, "glib main-loop thread name (null-bounded)"),
    (b"gdbus\x00", "safe", False, "glib dbus thread name (null-bounded)"),
    (b"frida-main-loop", "safe", False, "thread/GSource name (main loop)"),
    (b"frida-eternal-agent", "safe", False, "thread name (eternal agent) -> comm 'frida-eternal-a'"),
    (b"frida-generate-certificate", "safe", False, "thread name (TLS cert-gen) -> comm 'frida-generate-'"),
    # Standalone (null-bounded) "frida" = the prgname GLib feeds into "pool-%s",
    # which is why a `pool-frida` worker thread appears in the target even though
    # the literal "pool-frida" is never in the binary. Null-bounding keeps this
    # from matching substrings like "libfrida" / "re.frida.server".
    (b"\x00frida\x00", "safe", True, "bare 'frida' prgname -> GLib pool-%s (the pool-frida thread)"),

    (b"FridaScriptEngine", "signature", False, "script engine identity, lives in the agent"),
    (b"frida/runtime/", "signature", False, "JS runtime sourcemap paths in the agent"),
    (b"frida-gum", "signature", False, "gum sourcemap paths in the agent"),
    (b"GumScript", "signature", False, "gum script identity"),
    (b"GumInterceptor", "signature", False, "gum interceptor identity (in-memory marker)"),

    (b"frida:rpc", "rpc", True, "RPC message tag - client and agent must agree"),

    (b"frida", "aggressive", False, "bare leftovers: symbol names, frida.Error.* "
                                    "wire strings, the Frida JS global"),
]

# Which fingerprint tokens each binary-fixable detection actually depends on.
# Drives the coverage report: a vector is only "covered" when every indicator
# token present in THIS build was patched; one left intact downgrades it to
# "partial" and names the flag that would finish it. Tokens must match PATTERNS
# byte-for-byte (including the null boundaries on gmain/gdbus/frida).
DETECTION_TOKENS = {
    "proc-maps-scan":        [b"frida-agent", b"re.frida.server", b"linjector"],
    "thread-name-scan":      [b"gmain\x00", b"gdbus\x00", b"gum-js-loop",
                              b"pool-spawner", b"\x00frida\x00", b"frida-main-loop",
                              b"frida-eternal-agent", b"frida-generate-certificate"],
    "process-scan":          [b"frida-server", b"frida-helper", b"frida-inject",
                              b"linjector"],
    "file-artifact-scan":    [b"re.frida.server", b"frida-agent"],
    "unix-socket-scan":      [b"linjector"],
    "memory-signature-scan": [b"LIBFRIDA", b"libfrida", b"FridaScriptEngine",
                              b"GumScript", b"GumInterceptor", b"frida-gum",
                              b"frida/runtime/"],
}
DETECTION_SCAN_TOKENS = {t for toks in DETECTION_TOKENS.values() for t in toks}

E_MACHINE = {0x03: "x86", 0x28: "arm", 0x3E: "x86_64", 0xB7: "arm64"}

# The four architectures frida publishes an android frida-server for.
# "arm" is 32-bit ARM (armeabi-v7a), "arm64" is aarch64 (arm64-v8a).
FRIDA_ANDROID_ARCHES = ("arm", "arm64", "x86", "x86_64")

FRIDA_RELEASE_URL = ("https://github.com/frida/frida/releases/download/"
                     "{ver}/frida-server-{ver}-android-{arch}.xz")

DEFAULT_CONTROL_PORT = 27042
DEFAULT_CLUSTER_PORT = 27043


# --------------------------------------------------------------------------
# Minimal ELF reader - we only need arch and the .text bounds.
# --------------------------------------------------------------------------

class ElfInfo:
    def __init__(self, data: bytes):
        if data[:4] != b"\x7fELF":
            raise ValueError("not an ELF file (bad magic)")
        self.is64 = data[4] == 2
        self.end = "<" if data[5] == 1 else ">"
        self.machine = struct.unpack_from(self.end + "H", data, 0x12)[0]
        self.arch = E_MACHINE.get(self.machine, "unknown-0x%x" % self.machine)
        self.text = self._find_text(data)

    def _find_text(self, data: bytes):
        try:
            e = self.end
            if self.is64:
                shoff = struct.unpack_from(e + "Q", data, 0x28)[0]
                shent, shnum, shstr = struct.unpack_from(e + "HHH", data, 0x3A)
                off_field, size_field = 0x18, 0x20
                fmt = e + "Q"
            else:
                shoff = struct.unpack_from(e + "I", data, 0x20)[0]
                shent, shnum, shstr = struct.unpack_from(e + "HHH", data, 0x2E)
                off_field, size_field = 0x10, 0x14
                fmt = e + "I"
            if not shoff or not shnum:
                return None

            def sect(i):
                base = shoff + i * shent
                name = struct.unpack_from(e + "I", data, base)[0]
                off = struct.unpack_from(fmt, data, base + off_field)[0]
                size = struct.unpack_from(fmt, data, base + size_field)[0]
                return name, off, size

            _, stroff, strsize = sect(shstr)
            strtab = data[stroff:stroff + strsize]
            for i in range(shnum):
                name, off, size = sect(i)
                nm = strtab[name:strtab.find(b"\x00", name)]
                if nm == b".text":
                    return (off, off + size)
        except Exception:
            pass
        return None


# --------------------------------------------------------------------------
# Protected regions - the string rewriter must NEVER touch these.
#
# frida-server embeds one frida-agent .so PER architecture. The string tokens
# we rename also occur inside those embedded agents: in .rodata (harmless data)
# but also in .dynstr / .dynsym / .gnu.hash and even .text. Renaming a symbol
# name in an agent's .dynstr without rebuilding its GNU hash table breaks that
# agent's symbol resolution at load time - and since the agent is only mmap'd
# into the target during SPAWN, the result is exactly: `frida-ps` works, but
# `-f` dies with "bootstrapper crashed with signal 11". So we carve out every
# symbol/hash/reloc/executable section, in the main binary and every embedded
# ELF, and skip any string hit that overlaps one. (Port immediates are handled
# separately and are opcode-anchored, so they are unaffected by this.)
# --------------------------------------------------------------------------

SHF_EXECINSTR = 0x4
SHT_PROGBITS = 1
FATAL_SECTIONS = {
    ".dynstr", ".dynsym", ".symtab", ".strtab", ".gnu.hash", ".hash",
    ".gnu.version", ".gnu.version_r", ".gnu.version_d",
    ".rela.dyn", ".rela.plt", ".rel.dyn", ".rel.plt",
    ".plt", ".plt.got", ".plt.sec", ".got", ".got.plt",
    ".init", ".fini", ".init_array", ".fini_array",
}


def iter_elf_sections(data: bytes, base: int):
    """Yield (name, flags, abs_off, size) for the ELF whose header is at `base`.
    Tolerant: returns [] on anything that does not parse cleanly."""
    try:
        if data[base:base + 4] != b"\x7fELF":
            return []
        is64 = data[base + 4] == 2
        e = "<" if data[base + 5] == 1 else ">"
        if is64:
            shoff = struct.unpack_from(e + "Q", data, base + 0x28)[0]
            shent, shnum, shstr = struct.unpack_from(e + "HHH", data, base + 0x3A)
            flag_o, off_o, size_o, W = 0x08, 0x18, 0x20, e + "Q"
        else:
            shoff = struct.unpack_from(e + "I", data, base + 0x20)[0]
            shent, shnum, shstr = struct.unpack_from(e + "HHH", data, base + 0x2E)
            flag_o, off_o, size_o, W = 0x08, 0x10, 0x14, e + "I"
        if not shoff or not shnum or shstr >= shnum:
            return []

        def field(i, o, f):
            return struct.unpack_from(f, data, base + shoff + i * shent + o)[0]

        stroff = field(shstr, off_o, W)
        out = []
        for i in range(shnum):
            nname = struct.unpack_from(e + "I", data, base + shoff + i * shent)[0]
            styp = struct.unpack_from(e + "I", data, base + shoff + i * shent + 4)[0]
            fl = field(i, flag_o, W)
            off = field(i, off_o, W)
            size = field(i, size_o, W)
            z = data.find(b"\x00", base + stroff + nname)
            nm = data[base + stroff + nname:z].decode("latin1", "replace")
            out.append((nm, styp, fl, base + off, size))
        return out
    except Exception:
        return []


def _elf_header_sane(data: bytes, o: int) -> bool:
    """Reject a coincidental `\\x7fELF` whose program/section header tables fall
    outside the file. Without this, a stray magic inside agent data could parse
    as an 'embedded ELF' and manufacture a bogus oversized protected hole (which
    could then expose a real agent's symbol/hash tables and break spawn)."""
    try:
        is64 = data[o + 4] == 2
        e = "<" if data[o + 5] == 1 else ">"
        if is64:
            phoff = struct.unpack_from(e + "Q", data, o + 0x20)[0]
            shoff = struct.unpack_from(e + "Q", data, o + 0x28)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, o + 0x36)
            shentsize, shnum = struct.unpack_from(e + "HH", data, o + 0x3A)
        else:
            phoff = struct.unpack_from(e + "I", data, o + 0x1C)[0]
            shoff = struct.unpack_from(e + "I", data, o + 0x20)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, o + 0x2A)
            shentsize, shnum = struct.unpack_from(e + "HH", data, o + 0x2E)
        n = len(data)
        if shoff and o + shoff + shnum * shentsize > n:
            return False
        if phoff and o + phoff + phnum * phentsize > n:
            return False
        return True
    except Exception:
        return False


def find_embedded_elf_bases(data: bytes):
    """Every real ELF header in the file: offset 0 plus each embedded agent /
    helper. A bare `\\x7fELF` byte run is not enough - we also require a valid
    class, data-encoding, a known e_machine, and in-bounds header tables, so a
    coincidental magic inside some blob does not manufacture a bogus (and
    over-broad) protected range."""
    bases = [0]
    o = data.find(b"\x7fELF", 1)
    while o >= 0:
        try:
            if (data[o + 4] in (1, 2) and data[o + 5] in (1, 2)
                    and struct.unpack_from(
                        ("<" if data[o + 5] == 1 else ">") + "H", data, o + 0x12
                    )[0] in E_MACHINE
                    and _elf_header_sane(data, o)):
                bases.append(o)
        except Exception:
            pass
        o = data.find(b"\x7fELF", o + 1)
    return bases


def _merge(rs):
    rs = sorted(rs)
    out = []
    for s, e in rs:
        if out and s <= out[-1][1]:
            out[-1] = (out[-1][0], max(out[-1][1], e))
        else:
            out.append((s, e))
    return out


def _subtract(ranges, holes):
    """ranges minus holes (both lists of [start, end))."""
    holes = _merge(holes)
    out = []
    for s, e in ranges:
        segs = [(s, e)]
        for hs, he in holes:
            if he <= s or hs >= e:
                continue
            nxt = []
            for x, y in segs:
                if he <= x or hs >= y:
                    nxt.append((x, y))
                else:
                    if x < hs:
                        nxt.append((x, hs))
                    if he < y:
                        nxt.append((he, y))
            segs = nxt
        out.extend(segs)
    return _merge(out)


def protected_ranges(data: bytes):
    """Merged, sorted [start, end) byte ranges the string rewriter must avoid.

    frida-server's main .text is ~100 MB and the embedded per-arch agents live
    *inside* that file range, so simply protecting .text would freeze the agents
    whole - including their .rodata, where the thread-name literals the TARGET
    reads (gmain/gdbus/gum-js-loop) live. So we protect every ELF's fatal + exec
    sections, then re-open each embedded agent's non-fatal data (.rodata/.data):
    those string edits are length-preserving and touch no symbol/hash/code, so
    they keep spawn working while still de-fingerprinting the injected agent.
    """
    prot, holes, agent_fatal = [], [], []
    for b in find_embedded_elf_bases(data):
        for nm, styp, fl, off, size in iter_elf_sections(data, b):
            if not size:
                continue
            if (fl & SHF_EXECINSTR) or nm in FATAL_SECTIONS:
                prot.append((off, off + size))          # code / symtab / hash
                if b != 0:
                    agent_fatal.append((off, off + size))
            elif b != 0 and styp == SHT_PROGBITS:
                holes.append((off, off + size))         # agent .rodata/.data
    # Re-open agent PROGBITS data, then re-protect agent fatal sections on top,
    # so a mis-sized hole can never expose a symbol/hash/reloc/code region.
    return _merge(_subtract(_merge(prot), holes) + agent_fatal)


def overlaps_protected(ranges, starts, off: int, length: int) -> bool:
    """True if [off, off+length) intersects any protected range."""
    if not ranges:
        return False
    i = bisect.bisect_right(starts, off + length - 1) - 1
    for j in (i, i + 1):
        if 0 <= j < len(ranges):
            s, en = ranges[j]
            if off < en and off + length > s:
                return True
    return False


def elf_on_file_extent(data: bytes, base: int):
    """(base, end) covering the entire on-file image of the ELF at `base`:
    header + program headers + sections + section-header table. None if it does
    not parse cleanly. Used to fence the port-immediate rewrite out of the
    embedded agents, whose code lives inside the main binary's .text."""
    try:
        if data[base:base + 4] != b"\x7fELF":
            return None
        is64 = data[base + 4] == 2
        e = "<" if data[base + 5] == 1 else ">"
        end = base + (64 if is64 else 52)
        if is64:
            phoff = struct.unpack_from(e + "Q", data, base + 0x20)[0]
            shoff = struct.unpack_from(e + "Q", data, base + 0x28)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, base + 0x36)
            shentsize, shnum = struct.unpack_from(e + "HH", data, base + 0x3A)
            W, p_off_o, p_fsz_o = e + "Q", 0x08, 0x20
        else:
            phoff = struct.unpack_from(e + "I", data, base + 0x1C)[0]
            shoff = struct.unpack_from(e + "I", data, base + 0x20)[0]
            phentsize, phnum = struct.unpack_from(e + "HH", data, base + 0x2A)
            shentsize, shnum = struct.unpack_from(e + "HH", data, base + 0x2E)
            W, p_off_o, p_fsz_o = e + "I", 0x04, 0x10
        if phoff and phnum:
            end = max(end, base + phoff + phnum * phentsize)
            for k in range(phnum):
                ph = base + phoff + k * phentsize
                p_off = struct.unpack_from(W, data, ph + p_off_o)[0]
                p_fsz = struct.unpack_from(W, data, ph + p_fsz_o)[0]
                end = max(end, base + p_off + p_fsz)
        if shoff and shnum:
            end = max(end, base + shoff + shnum * shentsize)
        for _nm, _styp, _fl, off, size in iter_elf_sections(data, base):
            end = max(end, off + size)
        return (base, min(end, len(data)))
    except Exception:
        return None


def agent_extents(data: bytes):
    """Merged on-file ranges of every EMBEDDED ELF (per-arch agents/helpers),
    excluding the main binary at offset 0. The port-immediate rewrite subtracts
    these, so an agent's own code can never be mistaken for a port constant and
    corrupted (which would break spawn)."""
    ext = []
    for b in find_embedded_elf_bases(data):
        if b == 0:
            continue
        r = elf_on_file_extent(data, b)
        if r:
            ext.append(r)
    return _merge(ext)


# --------------------------------------------------------------------------
# Replacement generation - preserve length AND character class, so identifiers
# stay identifiers, filenames stay filenames, and separators survive.
# --------------------------------------------------------------------------

def mutate(token: bytes, rng: random.Random) -> bytes:
    out = bytearray()
    for ch in token.decode("ascii"):
        if ch.islower():
            out += rng.choice(string.ascii_lowercase).encode()
        elif ch.isupper():
            out += rng.choice(string.ascii_uppercase).encode()
        elif ch.isdigit():
            out += rng.choice(string.digits).encode()
        else:
            out += ch.encode()
    return bytes(out)


def make_replacement(token: bytes, rng: random.Random) -> bytes:
    # Never emit something that is itself a signature.
    for _ in range(64):
        cand = mutate(token, rng)
        low = cand.lower()
        if b"frida" not in low and b"gum" not in low and cand != token:
            return cand
    raise RuntimeError("could not generate a clean replacement for %r" % token)


# --------------------------------------------------------------------------
# Port immediates
# --------------------------------------------------------------------------

def port_encodings(arch: str, imm: int):
    """Anchored encodings that materialise `imm` as a constant in code.

    Each entry is (match_pattern, align, label, patch_off, patch_len):
      match_pattern  the exact bytes to search for, INCLUDING the opcode, so a
                     bare data word or an unrelated instruction whose operand
                     merely equals `imm` - e.g. a `call rel32` whose displacement
                     happens to be the port - is never matched.
      patch_off/len  the sub-range of the match to overwrite (the immediate
                     itself), leaving the opcode / prefix bytes untouched.

    RISC arches fold opcode+imm into one 4-byte word, so the whole instruction
    is rewritten (patch_off=0, patch_len=4). x86 opcodes are variable-length, so
    we anchor on the opcode byte and rewrite ONLY the 4 immediate bytes - this is
    what stops the x86 false-positives (call displacements, jump tables, data)
    that a bare value scan produced. The old-port and new-port lists are
    index-aligned, so callers can zip them. Unknown arch -> [] (rely on -l).
    """
    out = []
    imm32 = struct.pack("<I", imm)
    if arch == "arm64":
        # movz/movk w|x, #imm : imm lives in bits [20:5]; rewrite whole insn.
        for base, tag in ((0x52800000, "movz w"), (0xD2800000, "movz x"),
                          (0x72800000, "movk w"), (0xF2800000, "movk x")):
            for rd in range(31):
                out.append((struct.pack("<I", base | (imm << 5) | rd), 4,
                            "%s%d" % (tag, rd), 0, 4))
    elif arch == "arm":
        # 32-bit ARM. Android armeabi-v7a is normally built Thumb-2, but some
        # objects are ARM (A32), so emit BOTH encodings of the 16-bit MOVW.
        # A32 MOVW rd,#imm : cond=AL, whole 4-byte insn, 4-byte aligned.
        for rd in range(15):
            insn = 0xE3000000 | ((imm & 0xF000) << 4) | (rd << 12) | (imm & 0xFFF)
            out.append((struct.pack("<I", insn), 4, "movw(a32) r%d" % rd, 0, 4))
        # Thumb-2 MOVW rd,#imm (T3) : two little-endian halfwords, 2-byte aligned.
        #   imm16 = imm4:i:imm3:imm8 ; hw1 = 11110 i 100100 imm4 ; hw2 = 0 imm3 Rd imm8
        i_bit = (imm >> 11) & 1
        imm4 = (imm >> 12) & 0xF
        imm3 = (imm >> 8) & 0x7
        imm8 = imm & 0xFF
        hw1 = 0xF240 | (i_bit << 10) | imm4
        for rd in range(13):            # r0-r12 ; MOVW never targets SP/PC
            hw2 = (imm3 << 12) | (rd << 8) | imm8
            out.append((struct.pack("<HH", hw1, hw2), 2,
                        "movw(t2) r%d" % rd, 0, 4))
    elif arch in ("x86", "x86_64"):
        # mov r32, imm32  ==  (B8+rd) imm32 : anchor on opcode, rewrite the imm.
        regs = ("eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi")
        for rd, name in enumerate(regs):
            out.append((bytes([0xB8 + rd]) + imm32, 1, "mov %s" % name, 1, 4))
        # REX.B + mov r32, imm32  ==  (41 B8+rd) imm32 : r8d..r15d.
        for rd in range(8):
            out.append((bytes([0x41, 0xB8 + rd]) + imm32, 1,
                        "mov r%dd" % (8 + rd), 2, 4))
    # any other arch -> [] : skip immediate patching; the -l flag moves the port.
    return out


def disp(tok: bytes) -> str:
    """Printable form of a token/replacement (some carry null-byte boundaries)."""
    return tok.decode("ascii", "replace").replace("\x00", "\\0")


def find_all(data: bytes, needle: bytes, align: int = 1):
    hits, start = [], 0
    while True:
        i = data.find(needle, start)
        if i < 0:
            return hits
        if align == 1 or i % align == 0:
            hits.append(i)
        start = i + 1


# --------------------------------------------------------------------------
# Load / report helpers
# --------------------------------------------------------------------------

def fetch_server(version: str, arch: str, dest_dir: str = ".") -> str:
    """Download the stock android frida-server for `version`/`arch` from GitHub
    releases and return the local .xz path. Both are caller-specified."""
    if arch not in FRIDA_ANDROID_ARCHES:
        raise ValueError("arch must be one of %s (got %r)"
                         % (", ".join(FRIDA_ANDROID_ARCHES), arch))
    url = FRIDA_RELEASE_URL.format(ver=version, arch=arch)
    dest = os.path.join(dest_dir, os.path.basename(url))
    print("[*] fetching %s" % url)
    req = urllib.request.Request(url, headers={"User-Agent": "fridapatch"})
    try:
        with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as fh:
            shutil.copyfileobj(r, fh)
    except urllib.error.HTTPError as exc:
        hint = (" - check the version/arch; that release asset does not exist"
                if exc.code == 404 else "")
        raise RuntimeError("download failed: HTTP %s%s" % (exc.code, hint))
    except Exception as exc:
        raise RuntimeError("download failed: %s" % exc)
    print("[+] saved %s (%d bytes)" % (dest, os.path.getsize(dest)))
    return dest


def load_binary(path: str) -> bytes:
    with open(path, "rb") as fh:
        raw = fh.read()
    if raw[:6] == b"\xfd7zXZ\x00" or path.endswith(".xz"):
        print("[*] input is xz-compressed, decompressing in memory")
        raw = lzma.decompress(raw)
    return raw


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def print_detections():
    print("\nAnti-Frida checks an APK can implement, and what mitigates each\n")
    width = max(len(d["id"]) for d in DETECTIONS)
    for d in DETECTIONS:
        tag = {"binary": "[BINARY]", "runtime": "[RUNTIME]"}[d["fix"]]
        print("  %-9s %-*s  %s" % (tag, width, d["id"], d["what"]))
        print("  %-9s %-*s  how : %s" % ("", width, "", d["how"]))
        print("  %-9s %-*s  fix : %s\n" % ("", width, "", d["note"]))
    nb = sum(1 for d in DETECTIONS if d["fix"] == "binary")
    print("  [BINARY]  %d checks - handled by this script." % nb)
    print("  [RUNTIME] %d checks - need a Frida-side hook; patching the server "
          "cannot help.\n" % (len(DETECTIONS) - nb))


# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

def main() -> int:
    ap = argparse.ArgumentParser(
        description="Patch a frida-server binary to survive in-APK anti-Frida checks.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__)
    ap.add_argument("binary", nargs="?", help="stock frida-server (.xz accepted)")
    ap.add_argument("--fetch", metavar="VERSION",
                    help="download the stock android frida-server for this "
                         "version from GitHub releases, then patch it "
                         "(requires --arch)")
    ap.add_argument("--arch", choices=FRIDA_ANDROID_ARCHES,
                    help="target arch for --fetch: %s"
                         % ", ".join(FRIDA_ANDROID_ARCHES))
    ap.add_argument("-o", "--output", help="output path (default: <input>-patched)")
    ap.add_argument("-n", "--name", default="sysmon",
                    help="filename to push as on-device (default: sysmon)")
    ap.add_argument("-p", "--port", type=int,
                    help="control port, 10000-65534 (default: random)")
    ap.add_argument("-s", "--seed", type=int,
                    help="RNG seed, for a reproducible build")
    ap.add_argument("--patch-port", action="store_true",
                    help="also rewrite the hardcoded default port in .text, so "
                         "the server listens correctly with no -l flag")
    ap.add_argument("--patch-signatures", action="store_true",
                    help="rewrite in-process memory-scan markers: "
                         "FridaScriptEngine, GumScript, and the frida-gum / "
                         "frida/runtime/ sourcemap paths carried in the agent")
    ap.add_argument("--patch-rpc", action="store_true",
                    help="rewrite frida:rpc. WARNING: hangs '-f' spawn unless you "
                         "ALSO patch the host client (frida/core.py) to the same "
                         "tag - server-only leaves host<->agent RPC mismatched. "
                         "See README. Leave off unless you know you need it.")
    ap.add_argument("--aggressive", action="store_true",
                    help="everything above plus bare 'frida' leftovers. Expect "
                         "breakage: this hits frida.Error.* wire strings and the "
                         "Frida JS global that scripts call.")
    ap.add_argument("--keep", action="append", default=[], metavar="TOKEN",
                    help="leave this token untouched (repeatable)")
    ap.add_argument("--max-port-sites", type=int, default=16,
                    help="refuse --patch-port above this many hits (default: 16)")
    ap.add_argument("--force", action="store_true",
                    help="proceed past the port-site safety limit")
    ap.add_argument("--check", action="store_true",
                    help="scan and report only, write nothing")
    ap.add_argument("--list-detections", action="store_true",
                    help="print the anti-Frida check catalog and exit")
    ap.add_argument("--push", action="store_true",
                    help="adb push the result and chmod it")
    ap.add_argument("--package", default="com.example.app",
                    help="package name to show in the example commands")
    args = ap.parse_args()

    if args.list_detections:
        print_detections()
        return 0

    # ---- fetch (optional) ------------------------------------------------
    if args.fetch:
        if args.binary:
            ap.error("give a binary OR --fetch, not both")
        if not args.arch:
            ap.error("--fetch requires --arch (one of %s)"
                     % ", ".join(FRIDA_ANDROID_ARCHES))
        try:
            args.binary = fetch_server(args.fetch, args.arch)
        except Exception as exc:
            print("[!] %s" % exc, file=sys.stderr)
            return 1
    elif args.arch:
        ap.error("--arch only applies with --fetch")
    if not args.binary:
        ap.error("give a frida-server path, or --fetch VERSION --arch ARCH "
                 "(or --list-detections)")

    # ---- load ------------------------------------------------------------
    try:
        data = load_binary(args.binary)
        elf = ElfInfo(data)
    except Exception as exc:
        print("[!] %s" % exc, file=sys.stderr)
        return 1

    # A --fetch download names the arch in its URL; make sure the bytes agree.
    if args.arch and elf.arch != args.arch:
        print("[!] fetched arch %s but the binary is %s - aborting"
              % (args.arch, elf.arch), file=sys.stderr)
        return 1

    buf = bytearray(data)
    print("[*] %s" % args.binary)
    print("    arch    : %s (%d-bit)" % (elf.arch, 64 if elf.is64 else 32))
    print("    size    : %d bytes" % len(data))
    print("    sha256  : %s" % sha256(data))
    text_desc = ("0x%x-0x%x" % elf.text if elf.text
                 else "not found (section headers stripped) - immediate scan will "
                      "cover the whole file")
    print("    .text   : %s" % text_desc)

    # ---- port ------------------------------------------------------------
    seed_val = args.seed if args.seed is not None else os.urandom(16)
    rng = random.Random(seed_val)                 # drives string replacements
    # Separate, deterministically-derived stream for the port, so that whether
    # -p is given never shifts the string replacements (reproducible builds).
    port_seed = hashlib.sha256(repr(seed_val).encode() + b"|port").digest()
    port_rng = random.Random(port_seed)
    if args.port is None:
        port = port_rng.randint(10000, 65534)
        while port in (DEFAULT_CONTROL_PORT, DEFAULT_CLUSTER_PORT):
            port = port_rng.randint(10000, 65534)
    else:
        port = args.port
    if not 10000 <= port <= 65534:
        print("[!] port must be 10000-65534 (5 digits, so the ASCII literal stays "
              "the same length)", file=sys.stderr)
        return 1
    if port in (DEFAULT_CONTROL_PORT, DEFAULT_CLUSTER_PORT):
        print("[!] --port %d is a Frida default; the default-port probe will "
              "still fire and --patch-port is a no-op. Pick a non-default port "
              "unless you meant to keep the default." % port)

    # ---- select tiers ----------------------------------------------------
    tiers = {"safe"}
    if args.patch_signatures:
        tiers.add("signature")
    if args.patch_rpc:
        tiers.add("rpc")
    if args.aggressive:
        tiers.update({"signature", "rpc", "aggressive"})
        print("\n[!] --aggressive rewrites frida.Error.* and the Frida JS global. "
              "If scripts start failing, drop back to --patch-signatures.")
    keep = {k.encode() for k in args.keep}

    selected = [p for p in PATTERNS if p[1] in tiers and p[0] not in keep]
    selected.sort(key=lambda p: len(p[0]), reverse=True)

    # ---- protected regions ----------------------------------------------
    # Never rewrite a string that lands in a symbol/hash/reloc/code region of
    # the main binary or of any embedded per-arch agent - doing so corrupts the
    # agent and makes spawn (`-f`) crash in the bootstrapper while `frida-ps`
    # still works.
    prot = protected_ranges(data)
    prot_starts = [s for s, _ in prot]
    n_agents = max(0, len(find_embedded_elf_bases(data)) - 1)
    print("\n[*] protected %d symbol/hash/reloc/code region(s) across the main "
          "binary + %d embedded agent(s); string hits there are skipped."
          % (len(prot), n_agents))

    # ---- detection-token presence (for an honest coverage report) --------
    # Scan the ORIGINAL bytes for every token any detection depends on, whether
    # or not its tier is enabled this run, so the coverage report can tell
    # "already clean / not in this build" from "needs another flag". Hits inside
    # a protected region don't count - they are never rewritten.
    found_tokens = set()
    for t in DETECTION_SCAN_TOKENS:
        if any(not overlaps_protected(prot, prot_starts, h, len(t))
               for h in find_all(data, t)):
            found_tokens.add(t)

    # ---- scan + patch strings -------------------------------------------
    print("\n[*] string indicators")
    print("    %-18s %-18s %5s %5s  %s"
          % ("token", "replacement", "hits", "skip", "role"))
    total = 0
    total_skipped = 0
    patched_tokens = set()
    for token, tier, functional, desc in selected:
        all_hits = find_all(buf, token)
        hits = [h for h in all_hits
                if not overlaps_protected(prot, prot_starts, h, len(token))]
        skipped = len(all_hits) - len(hits)
        total_skipped += skipped
        if not hits:
            print("    %-18s %-18s %5d %5d  %s"
                  % (disp(token), "-", 0, skipped, desc))
            continue
        repl = make_replacement(token, rng)
        for off in hits:
            buf[off:off + len(token)] = repl
        total += len(hits)
        patched_tokens.add(token)
        mark = "*" if functional else " "
        print("    %-18s %-18s %5d %5d %s %s"
              % (disp(token), disp(repl), len(hits), skipped, mark, desc))
        if functional and skipped:
            print("    %-18s   ^ %d occurrence(s) left inside a protected agent/"
                  "symbol region; the runtime path resolves from the patched "
                  "copies, so spawn stays intact." % ("", skipped))
    print("    (* = functionally resolved at runtime; every occurrence gets the "
          "same replacement)")
    if total_skipped:
        print("    (skip = occurrences inside a protected agent symbol/code "
              "region, left intact to keep spawn working)")

    if total == 0:
        print("\n[!] zero indicators found. This binary is already patched, or "
              "it is packed/compressed and the strings are not literal.")

    # ---- port patching ---------------------------------------------------
    # Counters kept separate on purpose: only a rewritten CONTROL-port
    # instruction immediate actually moves the port the server binds to, so only
    # that (and only for a NON-default port) may drop the -l flag later. ASCII
    # (help text) and cluster-port hits must never make the tool claim the port
    # is "compiled in".
    ascii_patched = ctrl_imm_patched = clus_imm_patched = 0
    if args.patch_port:
        print("\n[*] default-port rewrite  %d -> %d" % (DEFAULT_CONTROL_PORT, port))
        scan_lo, scan_hi = (elf.text if elf.text else (0, len(buf)))
        # The file's .text also contains the embedded per-arch agents; an
        # opcode+immediate pattern can collide with an unrelated constant in
        # agent code, and overwriting that corrupts the agent (spawn dies). So
        # scan main-server code only: .text minus every embedded agent's extent.
        code_segments = _subtract([(scan_lo, scan_hi)], agent_extents(data))
        # Snapshot the search space ONCE, before any write: the control and the
        # cluster pass must both see the ORIGINAL bytes, never each other's
        # edits. (Otherwise -p 27043 would make the cluster pass re-find and
        # clobber the control sites the control pass just wrote.) So plan every
        # site first, against the pre-write bytes, then apply.
        segs = [(lo, bytes(buf[lo:hi])) for lo, hi in code_segments]
        ascii_sites = []   # (off, new5, label)
        imm_sites = []     # (insn_off, poff, new_bytes, tag, label, is_ctrl)
        for old_val, new_val, label, is_ctrl in (
                (DEFAULT_CONTROL_PORT, port, "control", True),
                (DEFAULT_CLUSTER_PORT, port + 1, "cluster", False)):
            if old_val == new_val:
                continue   # requested port already equals this default - no-op
            # ASCII literal (help/usage text) - cosmetic, never the bind port.
            # Length-preserving (5 digits), stand-alone digits, skip protected.
            asc_old, asc_new = str(old_val).encode(), str(new_val).encode()
            for off in find_all(buf, asc_old):
                if overlaps_protected(prot, prot_starts, off, 5):
                    continue
                before = buf[off - 1:off]
                after = buf[off + 5:off + 6]
                if (before and before.isdigit()) or (after and after.isdigit()):
                    continue
                ascii_sites.append((off, asc_new, label))

            # Instruction immediates, MAIN-SERVER code only, opcode-anchored per
            # arch (see port_encodings), so a data word or an unrelated insn that
            # merely contains `imm` is never overwritten.
            olds = port_encodings(elf.arch, old_val)
            news = port_encodings(elf.arch, new_val)
            sites = []
            for (opat, align, tag, poff, plen), (npat, *_) in zip(olds, news):
                for seg_lo, seg in segs:
                    for off in find_all(seg, opat):
                        abs_off = seg_lo + off
                        if abs_off % align == 0:
                            sites.append((abs_off, poff,
                                          npat[poff:poff + plen], tag))
            if len(sites) > args.max_port_sites and not args.force:
                print("    [!] %d immediate sites for %d - above --max-port-sites "
                      "(%d); skipped. Re-run with --force to patch anyway, or "
                      "just use the -l flag."
                      % (len(sites), old_val, args.max_port_sites))
                continue
            for insn_off, poff, wbytes, tag in sites:
                imm_sites.append((insn_off, poff, wbytes, tag, label, is_ctrl))

        # Apply (every site was located against the pre-write snapshot).
        for off, new5, label in ascii_sites:
            buf[off:off + 5] = new5
            ascii_patched += 1
            print("    ascii     0x%08x  %s (cosmetic)" % (off, label))
        for insn_off, poff, wbytes, tag, label, is_ctrl in imm_sites:
            buf[insn_off + poff:insn_off + poff + len(wbytes)] = wbytes
            if is_ctrl:
                ctrl_imm_patched += 1
            else:
                clus_imm_patched += 1
            print("    %-9s 0x%08x  %s" % (tag, insn_off, label))

        if ascii_patched + ctrl_imm_patched + clus_imm_patched == 0:
            print("    no default-port sites found - the -l flag below is the "
                  "authoritative way to move the port.")
        elif ctrl_imm_patched == 0:
            print("    [!] no CONTROL-port instruction immediate was rewritten "
                  "(%d ascii / %d cluster hit(s) only); the compiled-in bind "
                  "port is UNCHANGED - you must still pass -l 127.0.0.1:%d."
                  % (ascii_patched, clus_imm_patched, port))
    else:
        print("\n[*] default port left at %d in the binary; the -l flag below "
              "moves the listener to %d." % (DEFAULT_CONTROL_PORT, port))

    # Dropping -l is justified only by a real control-port immediate rewrite to a
    # NON-default port (a default port can't beat the default-port probe anyway).
    port_compiled_in = (ctrl_imm_patched > 0
                        and port not in (DEFAULT_CONTROL_PORT, DEFAULT_CLUSTER_PORT))

    # ---- verify ----------------------------------------------------------
    out = bytes(buf)
    print("\n[*] verification")
    ok = True
    if len(out) != len(data):
        print("    [!] SIZE CHANGED %d -> %d" % (len(data), len(out)))
        ok = False
    else:
        print("    size unchanged           %d bytes" % len(out))
    print("    output sha256            %s" % sha256(out))
    try:
        ElfInfo(out)
        print("    ELF header still valid   yes")
    except Exception as exc:
        print("    [!] ELF header broken: %s" % exc)
        ok = False

    # Residual = a patchable (non-protected) occurrence that survived. Hits
    # inside protected agent symbol/code regions are left on purpose and must
    # NOT count as a failure.
    residual = []
    for token, tier, _, _ in selected:
        live = [h for h in find_all(out, token)
                if not overlaps_protected(prot, prot_starts, h, len(token))]
        if live:
            residual.append("%s x%d" % (disp(token), len(live)))
    print("    patched tokens remaining %s"
          % (", ".join(residual) if residual else "none"))
    if residual:
        ok = False

    for probe in (b"frida", b"Frida", b"FRIDA", b"gum_", b"Gum"):
        n = len(find_all(out, probe))
        if n:
            note = "" if args.aggressive else "  (use --aggressive to strip)"
            if probe in (b"gum_", b"Gum"):
                note = "  (needs a source rebuild to remove safely)"
            print("    residual %-6s          x%d%s" % (probe.decode(), n, note))

    # ---- coverage --------------------------------------------------------
    # A binary vector is "covered" only when every one of its indicator tokens
    # that is actually present in THIS build was patched. A token present but
    # left intact (its tier wasn't enabled, or it was --kept) downgrades the
    # vector to "partial" and names the flag that would finish it.
    tier_flag = {"signature": "--patch-signatures", "rpc": "--patch-rpc",
                 "aggressive": "--aggressive"}
    token_tier = {p[0]: p[1] for p in PATTERNS}
    print("\n[*] detection coverage")
    for d in DETECTIONS:
        did = d["id"]
        if d["fix"] == "runtime":
            print("    %-22s NOT COVERED  needs a Frida-side hook" % did)
            continue
        if did == "default-port-probe":
            state = ("covered (control port compiled in)" if port_compiled_in
                     else "covered via the -l flag (enable --patch-port to "
                          "compile it in)")
            print("    %-22s %s" % (did, state))
            continue
        present = [t for t in DETECTION_TOKENS.get(did, []) if t in found_tokens]
        if not present:
            state = "no matching indicators in this build"
        else:
            missing = [t for t in present if t not in patched_tokens]
            if not missing:
                state = "covered"
            else:
                flags = sorted({tier_flag[token_tier[t]] for t in missing
                                if token_tier.get(t) in tier_flag})
                done = len(present) - len(missing)
                state = ("partial (%d/%d) - enable %s"
                         % (done, len(present), ", ".join(flags)) if flags
                         else "partial (%d/%d) - --kept token(s) remain"
                         % (done, len(present)))
        print("    %-22s %s" % (did, state))

    if args.check:
        print("\n[*] --check: nothing written (%s)."
              % ("verification OK" if ok else "VERIFICATION FAILED"))
        return 0 if ok else 1
    if not ok:
        print("\n[!] verification failed - not writing output.", file=sys.stderr)
        return 1

    # ---- write -----------------------------------------------------------
    outpath = args.output or (args.binary.rsplit(".xz", 1)[0] + "-patched")
    with open(outpath, "wb") as fh:
        fh.write(out)
    os.chmod(outpath, 0o755)
    print("\n[+] wrote %s (mode 755)" % outpath)

    # ---- optional push ---------------------------------------------------
    devpath = "/data/local/tmp/%s" % args.name
    if args.push:
        print("\n[*] pushing to %s" % devpath)
        chmod = "chmod 755 %s" % shlex.quote(devpath)
        for cmd in (["adb", "push", outpath, devpath],
                    ["adb", "shell", "su", "-c", chmod]):
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                print("    [!] %s\n        %s" % (" ".join(cmd), r.stderr.strip()))
                break
        else:
            print("    ok")

    # ---- how to drive it -------------------------------------------------
    print("""
==============================================================
  PORT : %d      (cluster port %d)
  NAME : %s      -> %s
==============================================================

  # 1. stage it
  adb push %s %s
  adb shell "su -c 'chmod 755 %s'"

  # 2. start it (%s)
  adb shell "su -c '%s%s -D'"

  # 3. forward and drive
  adb forward tcp:%d tcp:%d
  frida-ps -H 127.0.0.1:%d
  frida -H 127.0.0.1:%d -f %s -l bypass.js --no-pause

  # NOTE: -U / frida-ps -U will NOT see this server. USB mode probes the
  # default port only - always use -H 127.0.0.1:%d.
""" % (port, port + 1,
       args.name, devpath,
       outpath, devpath,
       devpath,
       "port compiled in - no -l needed (fallback: -l 127.0.0.1:%d)" % port
       if port_compiled_in else "the -l flag is what moves the port",
       devpath, "" if port_compiled_in else " -l 127.0.0.1:%d" % port,
       port, port,
       port,
       port, args.package,
       port))
    return 0


if __name__ == "__main__":
    sys.exit(main())
