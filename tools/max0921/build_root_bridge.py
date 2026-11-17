"""Rebuild reviewed 0921 worker variants from the pinned AliceBridge asset."""

import argparse
import hashlib
from pathlib import Path
import struct
import subprocess
import tempfile
import zipfile


ASSEMBLY = r"""
.syntax unified
.arm
.text
    push {r4, r5, r6, lr}
    mov r4, r3
    movw ip, #0x87c0
    movt ip, #2
    blx ip
    mov r5, r0
DUMP_FIRST_ITER
    sub sp, sp, #24
    ldr r6, [r4, #12]
    str r6, [sp]
    ldr r6, [r4, #16]
    str r6, [sp, #4]
    ldr r6, [r4, #24]
    str r6, [sp, #8]
    ldr r6, [r4, #28]
    str r6, [sp, #12]
    str r5, [sp, #16]
    ldr r1, [r4]
    ldr r2, [r4, #4]
    ldr r3, [r4, #8]
    adr r0, message
    movw ip, #0xd168
    movt ip, #2
    blx ip
    mov r0, r5
    add sp, sp, #24
    pop {r4, r5, r6, pc}
message:
    .asciz "reclaim diag: valid=%u first=%d last=%d contiguous=%u same_flags=%u range_ok=%u unique=%u accepted=%u\n"
DUMP_FIRST_LABEL
"""

SCAN_RETRY = r"""
    .org 0x100
    push {r4, r5, r6, lr}
    mov r4, r0
    mov r5, r1
    mov r6, r2
    movw ip, #0x5bc0
    movt ip, #2
    blx ip
    cmp r0, #0
    beq retry_done
    mov r1, r4
    adr r0, retry_message
    movw ip, #0xd168
    movt ip, #2
    blx ip
    mov r0, r4
    mov r1, r5
    mov r2, r6
    movw ip, #0x5bc0
    movt ip, #2
    blx ip
retry_done:
    cmp r0, #0
    bne retry_return
    movw ip, #:lower16:RESUME_PA
    movt ip, #:upper16:RESUME_PA
    cmp r4, ip
    bne retry_return
    mov r1, r4
    adr r0, resumed_message
    movw ip, #0xd168
    movt ip, #2
    blx ip
    mov r0, #0
retry_return:
    pop {r4, r5, r6, pc}
retry_message:
    .asciz "scan diag: retry PA low=0x%08x\n"
resumed_message:
    .asciz "scan diag: resumed page read PA=0x%08x\n"
    .org 0x200
    push {r4, lr}
    movw ip, #0x5170
    movt ip, #2
    blx ip
    cmp r0, #0
    popeq {r4, pc}
    mov r4, r0
    adr r0, refresh_message
    movw ip, #0xd30c
    movt ip, #2
    blx ip
    mov r0, r4
    pop {r4, pc}
refresh_message:
    .asciz "scan diag: window refresh failed"
    .org 0x300
    movw r0, #:lower16:RESUME_PA
    movt r0, #:upper16:RESUME_PA
    cmp r0, r8
    blo keep_start
    ldr r1, [sp, #0x48]
    cmp r0, r1
    movlo r8, r0
keep_start:
    movw ip, #0x4494
    movt ip, #2
    bx ip
    .org 0x400
    push {r4, lr}
    mov r4, r0
    movw ip, #0x5170
    movt ip, #2
    blx ip
    cmp r0, #0
    popeq {r4, pc}
    adr r0, start_retry_message
    movw ip, #0xd30c
    movt ip, #2
    blx ip
    mov r0, r4
    movw ip, #0x5170
    movt ip, #2
    blx ip
    pop {r4, pc}
start_retry_message:
    .asciz "scan diag: retry initial reader"
"""


DUMP_RING = r"""
    .org 0x500
dump_after_munmap:
    push {r4, lr}
    ldr r4, [sp, #0x24]
    mov r0, r4
    adr r1, label_after_munmap
    movw ip, #0x5700
    movt ip, #3
    blx ip
    pop {r4, lr}
    movw r0, #0xd40
    bx lr
label_after_munmap:
    .asciz "dump after munmap"
    .org 0x600
dump_after_usleep:
    push {r4, lr}
    ldr r4, [sp, #0x24]
    mov r0, r4
    adr r1, label_after_usleep
    movw ip, #0x5700
    movt ip, #3
    blx ip
    pop {r4, lr}
    movw r0, #0x21cb
    bx lr
label_after_usleep:
    .asciz "dump after usleep"
    .org 0x700
dump32:
    push {r4, r5, r6, r7, r8, lr}
    mov r4, r0
    mov r5, r1
    sub sp, sp, #32
    ldr r2, [r4, #0]
    ldr r3, [r4, #4]
    ldr r6, [r4, #8]
    str r6, [sp, #0]
    ldr r6, [r4, #12]
    str r6, [sp, #4]
    ldr r6, [r4, #16]
    str r6, [sp, #8]
    ldr r6, [r4, #20]
    str r6, [sp, #12]
    ldr r6, [r4, #24]
    str r6, [sp, #16]
    ldr r6, [r4, #28]
    str r6, [sp, #20]
    adr r0, dump_format
    mov r1, r5
    movw ip, #0xd168
    movt ip, #2
    blx ip
    add sp, sp, #32
    pop {r4, r5, r6, r7, r8, lr}
    bx lr
dump_format:
    .asciz "%s: %08x %08x %08x %08x %08x %08x %08x %08x\n"
"""


CRED_TRACE = r"""
    .org 0x500
trace_win:
    push {r4, r5, r6, r7, r8, r9, r10, r11, lr}
    ldr r4, [sp, #36]
    ldr r5, [sp, #40]
    ldr r6, [sp, #44]
    mov r8, r0
    mov r9, r1
    mov r10, r2
    mov r11, r3
    sub sp, sp, #20
    str r4, [sp]
    str r5, [sp, #4]
    str r6, [sp, #8]
    ldr r1, [r8, #0x14]
    adr r0, trace_win_start
    movw ip, #0xd168
    movt ip, #2
    blx ip
    mov r0, r8
    mov r1, r9
    mov r2, r10
    mov r3, r11
    movw ip, #0x60d0
    movt ip, #2
    blx ip
    mov r9, r0
    mov r1, r9
    ldr r2, [r8, #0x14]
    adr r0, trace_win_rc
    movw ip, #0xd168
    movt ip, #2
    blx ip
    add sp, sp, #20
    mov r0, r9
    pop {r4, r5, r6, r7, r8, r9, r10, r11, pc}
trace_win_start:
    .asciz "cred trace: win start idx=%u\n"
trace_win_rc:
    .asciz "cred trace: win rc=%d idx=%u\n"
    .org 0x600
trace_reader:
    push {r4, r5, r6, r7, r8, r9, r10, r11, lr}
    mov r8, r0
    sub sp, sp, #12
    ldr r1, [r8, #0x14]
    ldr r2, [r8, #0x20]
    adr r0, trace_reader_start
    movw ip, #0xd168
    movt ip, #2
    blx ip
    mov r0, r8
    movw ip, #0x5170
    movt ip, #2
    blx ip
    mov r9, r0
    mov r1, r9
    ldr r2, [r8, #0x20]
    adr r0, trace_reader_rc
    movw ip, #0xd168
    movt ip, #2
    blx ip
    mov r0, r9
    add sp, sp, #12
    pop {r4, r5, r6, r7, r8, r9, r10, r11, pc}
trace_reader_start:
    .asciz "cred trace: reader start idx=%u cycle=%u\n"
trace_reader_rc:
    .asciz "cred trace: reader rc=%d cycle=%u\n"
"""


def bl_target(address, word):
    immediate = word & 0xFFFFFF
    if immediate & 0x800000:
        immediate -= 0x1000000
    return address + 8 + immediate * 4


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--llvm-bin", type=Path, required=True)
    inputs = parser.add_mutually_exclusive_group()
    inputs.add_argument("--input-elf", type=Path, help="raw upstream root-bridge asset")
    inputs.add_argument("--apk", type=Path, help="optional AliceBridge 1.0.21 APK input")
    parser.add_argument("--output", type=Path, default=Path("root-bridge-diag"))
    parser.add_argument("--scan-retry", action="store_true")
    parser.add_argument("--resume-pa", type=lambda value: int(value, 0), default=0)
    parser.add_argument("--initial-retry", action="store_true")
    parser.add_argument("--dump-ring", action="store_true")
    parser.add_argument("--cred-trace", action="store_true")
    args = parser.parse_args()
    if args.initial_retry and not args.scan_retry:
        parser.error("--initial-retry requires --scan-retry")
    if args.cred_trace and not args.scan_retry:
        parser.error("--cred-trace requires --scan-retry to keep the verified scan path")
    if args.cred_trace and args.dump_ring:
        parser.error("--cred-trace and --dump-ring use overlapping payload slots")
    if args.resume_pa and (
        not args.scan_retry or not 0x1080000 <= args.resume_pa < 0x29BA000
        or args.resume_pa % 4096
    ):
        parser.error("--resume-pa requires --scan-retry and a page within the 0921 kernel image")

    if args.apk:
        with zipfile.ZipFile(args.apk) as apk:
            original = apk.read("assets/max/root-bridge")
    else:
        asset = args.input_elf or (
            Path(__file__).resolve().parents[2]
            / "station/src/main/assets/max/root-bridge"
        )
        original = asset.read_bytes()
    expected_hash = "f53c3e127a95b8f78b0934ccea73382964d35fd7b3dd21b8b0ce258f50704474"
    if hashlib.sha256(original).hexdigest() != expected_hash:
        raise SystemExit("Unsupported root-bridge SHA-256; expected the reviewed 1.0.21 asset")

    hook_offset = 0x5798
    hook_address = 0x25798
    scan_offset = 0x44A0
    scan_address = 0x244A0
    resume_address = 0x24470
    initial_scan_address = 0x235FC
    refresh_hooks = ((0x25C18, 0xEBFFFD54), (0x25C78, 0xEBFFFD3C))
    cred_trace_sites = (0x25F6C, 0x25FC4, 0x25FFC, 0x2603C, 0x26088)
    payload_offset = 0x15000
    payload_address = 0x35000
    rx_header = 0x74
    expected_rx = (1, 0x32E0, 0x232E0, 0x232E0, 0xE590, 0xE590, 5, 0x10000)
    if (
        len(original) != 0x14D54
        or struct.unpack_from("<8I", original, rx_header) != expected_rx
        or struct.unpack_from("<I", original, hook_offset)[0] != 0xEB000C08
        or struct.unpack_from("<I", original, scan_offset)[0] != 0xEB0005C6
        or struct.unpack_from("<I", original, resume_address - 0x20000)[0] != 0xEA000007
        or struct.unpack_from("<I", original, initial_scan_address - 0x20000)[0] != 0xEB0006DB
        or struct.unpack_from("<I", original, 0x56D0)[0] != 0xE3000D40
        or struct.unpack_from("<I", original, 0x56DC)[0] != 0xE30201CB
        or any(
            bl_target(site, struct.unpack_from("<I", original, site - 0x20000)[0]) != 0x260D0
            for site in cred_trace_sites
        )
        or bl_target(0x26138, struct.unpack_from("<I", original, 0x6138)[0]) != 0x25170
        or any(
            struct.unpack_from("<I", original, address - 0x20000)[0] != instruction
            for address, instruction in refresh_hooks
        )
    ):
        raise SystemExit("Unsupported root-bridge layout")

    with tempfile.TemporaryDirectory(dir=Path.cwd()) as directory:
        source = Path(directory) / "trace.s"
        obj = source.with_suffix(".o")
        raw = source.with_suffix(".bin")
        retry_source = SCAN_RETRY.replace("RESUME_PA", hex(args.resume_pa))
        first_iter = (
            "    cmp r10, #24\n"
            "    bne 1f\n"
            "    ldr r0, [sp, #0x2c]\n"
            "    adr r1, label_first_iter\n"
            "    movw ip, #0x5700\n"
            "    movt ip, #3\n"
            "    blx ip\n"
            "1:\n"
        ) if args.dump_ring else ""
        first_label = (
            "label_first_iter:\n"
            "    .asciz \"dump first iter\"\n"
        ) if args.dump_ring else ""
        source.write_text(
            ASSEMBLY.replace("DUMP_FIRST_ITER", first_iter).replace(
                "DUMP_FIRST_LABEL", first_label
            )
            + (retry_source if args.scan_retry else "")
            + (DUMP_RING if args.dump_ring else "")
            + (CRED_TRACE if args.cred_trace else ""),
            encoding="ascii",
        )
        subprocess.run(
            [args.llvm_bin / "clang.exe", "--target=armv7a-linux-androideabi28",
             "-c", source, "-o", obj],
            check=True,
        )
        subprocess.run(
            [args.llvm_bin / "llvm-objcopy.exe", "-O", "binary", "-j", ".text", obj, raw],
            check=True,
        )
        payload = raw.read_bytes()

    patched = bytearray(original)
    patched.extend(bytes(payload_offset - len(original)))
    patched.extend(payload)
    segment_size = len(patched) - expected_rx[1]
    struct.pack_into("<2I", patched, rx_header + 16, segment_size, segment_size)
    displacement = (payload_address - hook_address - 8) // 4
    struct.pack_into("<I", patched, hook_offset, 0xEB000000 | displacement)
    if args.scan_retry:
        displacement = (payload_address + 0x100 - scan_address - 8) // 4
        struct.pack_into("<I", patched, scan_offset, 0xEB000000 | displacement)
        for address, _ in refresh_hooks:
            displacement = (payload_address + 0x200 - address - 8) // 4
            struct.pack_into("<I", patched, address - 0x20000, 0xEB000000 | displacement)
    if args.resume_pa:
        displacement = (payload_address + 0x300 - resume_address - 8) // 4
        struct.pack_into("<I", patched, resume_address - 0x20000, 0xEA000000 | displacement)
    if args.initial_retry:
        displacement = (payload_address + 0x400 - initial_scan_address - 8) // 4
        struct.pack_into("<I", patched, initial_scan_address - 0x20000, 0xEB000000 | displacement)
    if args.dump_ring:
        displacement = (payload_address + 0x500 - 0x256D0 - 8) // 4
        struct.pack_into("<I", patched, 0x56D0, 0xEB000000 | displacement)
        displacement = (payload_address + 0x600 - 0x256DC - 8) // 4
        struct.pack_into("<I", patched, 0x56DC, 0xEB000000 | displacement)
    if args.cred_trace:
        for site in cred_trace_sites:
            displacement = (payload_address + 0x500 - site - 8) // 4
            struct.pack_into("<I", patched, site - 0x20000, 0xEB000000 | displacement)
        displacement = (payload_address + 0x600 - 0x26138 - 8) // 4
        struct.pack_into("<I", patched, 0x6138, 0xEB000000 | displacement)
    with args.output.open("xb") as output:
        output.write(patched)
    print(f"{args.output}: sha256={hashlib.sha256(patched).hexdigest()}")


if __name__ == "__main__":
    main()
