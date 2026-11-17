# Temporary init-root: Station Max Zigbee YNDX-00053 / 0921

This contribution contains a reproducible native-worker variant and device
validation evidence for maintainer integration. It does not select a new worker
in the application or replace the existing `max/root-bridge` asset.

## Verified target

- Model reported by the owner: YNDX-00053, Station Max with Zigbee.
- Platform: `yandexstation_2`; Android 9 / SDK 28; AArch64.
- Kernel: 4.9.113, built 2026-10-16.
- Exact fingerprint:
  `Yandex/yandexstation_2/yandexstation_2:9/PPR1.180610.011/5000000921:user/release-keys`.
- AliceBridge version: 1.0.21. Tests used an ADB-only clone with automatic
  `MaxSetup.ensure` disabled, followed by a manually authorized native invocation.

The fingerprint identifies firmware, not hardware revision. It must not be used
as proof that YNDX-0008 and YNDX-00053 are interchangeable. Other revisions and
builds have not been validated by these device tests.

## Reproduce the tested worker

Use Python 3 and the Windows LLVM tools from Android NDK 28.2.13676358. From the
repository root:

```powershell
python tools/max0921/build_root_bridge.py `
  --llvm-bin '<Android NDK LLVM bin>' `
  --scan-retry --resume-pa 0x2258000 --cred-trace `
  --output root-bridge-0921-cred-trace
Get-FileHash root-bridge-0921-cred-trace -Algorithm SHA256
```

The default input is the existing repository asset
`station/src/main/assets/max/root-bridge`. `--input-elf` accepts another raw copy;
`--apk` accepts the original 1.0.21 APK. The builder verifies the complete input
SHA-256 and expected instruction layout before patching. It refuses to overwrite
an existing output. Building performs no device operations.

| Artifact | SHA-256 |
| --- | --- |
| Original 1.0.21 root-bridge asset | `f53c3e127a95b8f78b0934ccea73382964d35fd7b3dd21b8b0ce258f50704474` |
| Tested credentials-trace variant | `6a21d2a477bd45fba4a63d2dc8605bd285b1449ab38a3b983b0e6f63d4f9bdc3` |

The bounded scan changes resume the primary scan at PA `0x2258000` after the
existing image/layout checks and retry a failed page read once. The credentials
trace logs the index and return code around the five existing `win_write32`
calls and its internal `reader_cycle` call. The input's `init_task` and
credentials validation, 24-block reader limit, 200 ms delay and write order are
retained. `--initial-retry` affects `esc-scan`, not the tested `esc-bridge` path;
it is deliberately absent from the recipe above.

`--dump-ring` is a separate diagnostic variant and cannot be combined with
`--cred-trace`, because their payload slots overlap. Neither mode is a new
retry policy. Logging itself can affect timing, so a future build without the
trace needs its own validation.

## Device evidence, 7 November 2026

Two credentials-trace runs on separate boots passed all of these checks in the
same worker, immediately after READY and before any SID-changing command:

```text
bridge: worker READY
Uid:    0    0    0    0
CapPrm: 0000003fffffffff
CapEff: 0000003fffffffff
CapBnd: 0000003fffffffff
u:r:init:s0
```

The first trace recorded five successful writes with indices 25 through 30;
the second recorded indices 11 through 16. In both, the internal reader was not
called during credentials writes. Both workers were later closed with `exit`
and returned BYE. Ordinary ADB remained UID 2000 with SELinux Enforcing.

| Complete local evidence log | SHA-256 |
| --- | --- |
| First successful credentials trace | `d9efda3bf518540a1d9271415e5817c929fb4b34f8da1ee261e47a115388e295` |
| Second successful credentials trace, including BYE | `9226bac4ffffffbaf0872af59ea24b20bcce3b6d082d7eaf3ab1e5d3158552f9` |

Raw device logs, APKs, firmware images, device identifiers and credentials are
not included in this contribution. The excerpts above are the relevant identity
and lifecycle observations.

## Known failure and limits

Earlier runs of the scan/dump variants failed with `no reclaim`, including one
after a partial credentials update: the exiting parent showed UID 0 but
CapEff=0, never produced READY, and was not accepted as an init-root worker.
That failure remains unexplained at the exact capabilities-write step. It did
not reproduce in the two credentials-trace runs; this does not demonstrate
that the underlying timing-dependent failure has been corrected.

The first successful trace itself had a failed reader cycle during scanning,
then recovered on the existing read path. A successful session therefore does
not imply that every internal reclaim succeeded. Neither two successful boots
nor a log without GPU errors establishes success on every boot or full GPU
recovery after failure.

After BYE a parent can remain temporarily as a zombie named `esc36449` under
adbd. It no longer executes commands. A process check for only `root-bridge` and
`reader4` misses that renamed process; inspect its state as well. Do not stop a
shared adbd merely to reap it.

## Maintainer integration boundary

1. Keep exact firmware/architecture gates, original task/credentials checks and
   one attempt per boot. Preserve the boot reservation even after an early error;
   do not automatically restart the worker after a failed attempt.
2. Validate four UID zeros, required effective capability bits and the exact
   `u:r:init:s0` context from the worker itself before activating the transport.
   An intention-to-write log or a later shell-SID UID 0 command is insufficient.
3. Keep the existing worker available for other hardware until the shared
   fingerprint/hardware-selection question is resolved and reviewed.
4. Test the normal application flow separately. These tests do not validate the
   application's cache/recovery protection, runtime Permissive, ADB persistence,
   automatic setup trigger, or permanent root.

This is an experimental, repeatedly demonstrated temporary init-root path for
the stated device/build. The contribution is intended for review and integration,
not a claim of guaranteed reliability or completed end-to-end app support.
