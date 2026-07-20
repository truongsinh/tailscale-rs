# Building for Windows 7

`tailscale-rs` can be cross-built from Linux for Windows 7 via the
`x86_64-win7-windows-gnu` target. The result is a self-contained executable that links
only against DLLs present in a stock Win7 SP1 install.

```console
$ bin/build-win7 --example koidra_gateway
```

Artifacts land in `target/x86_64-win7-windows-gnu/release/`, stripped in place.

## Why the build is unusual

`x86_64-win7-windows-gnu` is a [Tier 3][tiers] target. Tier 3 means the target is *known
to the compiler* but nothing more: rust-lang CI does not build it, does not test it, and
rustup ships no prebuilt artifacts for it. Two consequences drive the whole recipe in
`bin/build-win7`:

1. **No prebuilt `std`.** We compile our own with `-Z build-std=std,panic_abort`, which is
   a nightly-only flag and needs the `rust-src` component. The workspace pins a stable
   toolchain in `rust-toolchain.toml`, so the script sets `RUSTUP_TOOLCHAIN=nightly` to
   override the pin for this build only — the pin still governs every other build.
2. **No linker probing.** The `x86_64-w64-mingw32-gcc` cross linker has to be named
   explicitly. It is set in `.cargo/config.toml` (and, redundantly but harmlessly, via
   `CARGO_TARGET_X86_64_WIN7_WINDOWS_GNU_LINKER` in the script, so the build works even if
   invoked from a directory where the config is not picked up).

The build runs in `rustlang/rust:nightly` rather than on the host so that neither the
nightly toolchain nor the mingw-w64 cross toolchain has to be installed locally. Besides
the linker, the image needs `cmake`, `nasm`, and `clang`: `russh` depends on `aws-lc-rs`,
whose build script compiles C and assembly.

## What Win7 support actually means here

The target differs from `x86_64-pc-windows-gnu` in that its `std` does not call APIs
introduced after Win7, and it does not set a `_WIN32_WINNT` floor above `0x0601`. That is
a compile-time property. It is not a guarantee that the binary runs correctly, because
nothing in rust-lang CI ever runs it. Validate on a real Win7 box before shipping.

The known risk areas, in the order they are likely to bite:

- **Dynamically probed APIs.** Some crates resolve symbols at runtime via `GetProcAddress`
  rather than importing them, so the import table alone does not prove what a binary
  calls. The RNG is the case worth knowing about: on the ordinary Windows targets
  `getrandom` uses `ProcessPrng`, which is Win10+. On this target it does not — the names
  that appear in the binary are `BCryptGenRandom` (bcrypt.dll, Vista+) and
  `SystemFunction036`, i.e. `RtlGenRandom` (advapi32.dll, XP+), both of which Win7 has.
  So the RNG is expected to work, but "expected" here means read off the binary, not
  observed on a Win7 box: nothing in rust-lang CI runs this path. It fails loudly and
  early if at all — the first RNG use is key generation at startup — so it is the
  cheapest thing to check first on-device.
- **Interactive PTY sessions are degraded.** ConPTY did not exist before Windows 10
  version 1809, so there is no supported way to allocate a pseudoconsole. Servers built
  from this tree refuse `pty-req` outright rather than pretend
  (see `examples/koidra_gateway`). Pipe-backed `shell` sessions and `exec` channels are
  unaffected and work normally; what you lose is terminal emulation — no line editing, no
  resize handling, and console programs that query the console handle directly will see a
  pipe and typically switch to non-interactive behaviour.
- **TLS root certificates.** Win7's certificate store predates the current Let's Encrypt
  chain. If a control or DERP endpoint's chain fails to validate on Win7 but validates
  everywhere else, suspect the platform trust store, not the code.

## Verifying an artifact

The point of the Tier 3 target is that the binary depends only on DLLs that ship with
Win7. Check that assumption directly rather than trusting the target name:

```console
$ x86_64-w64-mingw32-objdump -p \
      target/x86_64-win7-windows-gnu/release/examples/koidra_gateway.exe |
      grep 'DLL Name' | sort -u
```

Every name in the output should be a stock Win7 system DLL. As of the `koidra_gateway` example
that is `advapi32`, `bcrypt`, `iphlpapi`, `kernel32`, `msvcrt`, `ntdll`, `oleaut32`, and
`ws2_32` — all present on a stock Win7 SP1 install (`bcrypt` since Vista).

What matters is not the exact list, which moves with the dependency graph, but that
nothing in it postdates Win7. Two things to look for specifically:

- an `api-ms-win-*` API-set stub, or a `vcruntime*` / `ucrtbase` — something pulled in a
  newer Windows API surface or the UCRT, and the binary will fail to start on Win7 with a
  missing-DLL error.
- a DLL that exists on Win7 but whose *imported symbol* does not. The import table names
  the DLL, so a missing symbol also fails at load, just with a less obvious message.

Note that the release profile already sets `strip = true`, so the stripping step in
`bin/build-win7` is normally a no-op; it earns its place only when building under a
profile that does not strip.

[tiers]: https://doc.rust-lang.org/rustc/platform-support.html
