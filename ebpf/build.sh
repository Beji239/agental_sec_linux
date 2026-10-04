#!/usr/bin/env bash
# ebpf/build.sh -- compile the kernel camera.
#
# WHAT THIS DOES, AND THE PROBLEM IT SOLVES
#
# A BPF program is not interpreted: it is COMPILED, and the compiler has to be
# clang, because only clang can emit the `bpf` target with the BTF and CO-RE
# relocations the kernel's verifier and libbpf need.
#
# MEASURED ON THIS HOST, 2026-09-22: clang is NOT installed, and there is no
# passwordless sudo to install it. What IS present: gcc (no bpf target -- it
# answers "unrecognized command-line option '-target'"), bpftool v7.7 with
# `btf dump` and `gen skeleton`, libbpf.so.1, and a kernel with BTF.
#
# So this script has THREE ways to find a compiler, tried in order, and it
# NAMES WHICH ONE IT USED. That matters for a build artifact whose correctness
# depends on the toolchain: a .bpf.o built by a different clang than the one
# documented is a fact worth printing.
#
#   1. clang on PATH                     (the normal case on a dev machine)
#   2. a clang already unpacked under ebpf/.toolchain/ by an earlier run
#   3. a clang fetched AND UNPACKED WITHOUT ROOT, by downloading the Ubuntu
#      packages with `apt-get download` (which needs no privileges) and
#      extracting them with `dpkg-deb -x` into ebpf/.toolchain/
#
# THE THIRD PATH IS THE ONE THIS HOST USES, and it was verified before it was
# written: clang 18 is 80 kB of wrapper plus libLLVM, both fetchable, both
# extractable unelevated, and the resulting binary compiles a BPF object that
# `readelf` reports as `Machine: Linux BPF`. It is ~90 MB on disk, which is why
# it lives in .toolchain/ and is not committed.
#
# WHAT IT DOES NOT DO
#
# IT DOES NOT LOAD ANYTHING. Compiling is unelevated and safe; loading needs
# root and is a separate, deliberate act (ebpf/install.sh). A build script that
# asks for a password would make the build something an operator avoids.
#
# IT DOES NOT FETCH vmlinux.h FROM THE NETWORK IF IT CAN MAKE ONE. `bpftool btf
# dump file /sys/kernel/btf/vmlinux format c` produces the header for THIS
# kernel, which is strictly better than downloading one for a kernel that might
# not be this one. MEASURED: 3.5 MB, 166,868 lines, generated unelevated.
#
# IT FAILS LOUDLY. If no compiler can be found or the compile fails, it exits
# nonzero and says what to install. It never leaves a stale .bpf.o in place to
# be silently loaded, because a stale object is a camera trained on an older
# kernel's struct layouts -- it would load and produce nonsense.
set -uo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="$HERE/ebpf_monitor.bpf.c"
OUT="$HERE/ebpf_monitor.bpf.o"
TMP="$HERE/.build"
VMLINUX="$TMP/vmlinux.h"
TOOLCHAIN="$HERE/.toolchain"

mkdir -p "$TMP"

echo "ebpf build: $SRC"
echo "        -> $OUT"

# 1. vmlinux.h, from THIS kernel's BTF
if [[ -s "$VMLINUX" ]]; then
    echo "   vmlinux.h: reusing $(wc -l < "$VMLINUX") lines from a previous build"
else
    if ! command -v bpftool >/dev/null 2>&1; then
        echo "ERROR: bpftool is not installed, and without it there is no"
        echo "ERROR: vmlinux.h, and without vmlinux.h a CO-RE program cannot"
        echo "ERROR: be compiled. Install it with:"
        echo "ERROR:   sudo apt-get install linux-tools-common linux-tools-\$(uname -r)"
        echo "ERROR: NOTHING WAS BUILT."
        exit 1
    fi
    echo "   vmlinux.h: generating from /sys/kernel/btf/vmlinux (this kernel)"
    if ! bpftool btf dump file /sys/kernel/btf/vmlinux format c > "$VMLINUX" 2>"$TMP/btf.err"; then
        echo "ERROR: bpftool could not read /sys/kernel/btf/vmlinux."
        sed 's/^/ERROR:   /' "$TMP/btf.err" | head -5
        echo "ERROR: This kernel was built without BTF, so a CO-RE program"
        echo "ERROR: cannot be built OR loaded here. Nothing can be done from"
        echo "ERROR: userspace; the kernel would have to be replaced."
        echo "ERROR: NOTHING WAS BUILT."
        rm -f "$VMLINUX"
        exit 1
    fi
    echo "   vmlinux.h: $(wc -l < "$VMLINUX") lines"
fi

# 2. libbpf headers
INCLUDES=("-I$TMP")
if [[ -d /usr/include/bpf ]]; then
    INCLUDES+=("-I/usr/include")
    echo "   libbpf headers: /usr/include/bpf"
elif [[ -d "$TOOLCHAIN/usr/include/bpf" ]]; then
    INCLUDES+=("-I$TOOLCHAIN/usr/include")
    echo "   libbpf headers: $TOOLCHAIN/usr/include/bpf (unpacked, not installed)"
else
    echo "   libbpf headers: NOT FOUND -- trying to unpack them without root"
    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "ERROR: no libbpf headers and no dpkg-deb to unpack (or fetch) a"
        echo "ERROR: copy. Install them with:"
        echo "ERROR:   sudo apt-get install libbpf-dev"
        echo "ERROR: NOTHING WAS BUILT."
        exit 1
    fi
    mkdir -p "$TMP/dl" "$TOOLCHAIN"
    ( cd "$TMP/dl" && apt-get download libbpf-dev >/dev/null 2>&1 )
    deb=$(ls "$TMP/dl"/libbpf-dev_*.deb 2>/dev/null | head -1)
    if [[ -z "${deb:-}" ]]; then
        echo "ERROR: could not download libbpf-dev (no network, or no such"
        echo "ERROR: package on this release). Install it with:"
        echo "ERROR:   sudo apt-get install libbpf-dev"
        echo "ERROR: NOTHING WAS BUILT."
        exit 1
    fi
    dpkg-deb -x "$deb" "$TOOLCHAIN"
    INCLUDES+=("-I$TOOLCHAIN/usr/include")
    echo "   libbpf headers: unpacked from $(basename "$deb") into .toolchain/"
fi

# 3. a compiler, by the three paths
CLANG=""
USED=""
if command -v clang >/dev/null 2>&1; then
    CLANG="$(command -v clang)"
    USED="clang on PATH ($("$CLANG" --version 2>/dev/null | head -1))"
elif [[ -x "$TOOLCHAIN/usr/lib/llvm-18/bin/clang" ]]; then
    CLANG="$TOOLCHAIN/usr/lib/llvm-18/bin/clang"
    USED="an earlier unpack under .toolchain/ ($("$CLANG" --version 2>/dev/null | head -1))"
else
    echo "   clang: not installed and not unpacked yet"
    echo "   clang: fetching the packages AND UNPACKING THEM WITHOUT ROOT."
    echo "   clang: this is the path this host is expected to use; it needs"
    echo "   clang: no password. ~90 MB, kept in .toolchain/."
    if ! command -v dpkg-deb >/dev/null 2>&1; then
        echo "ERROR: no clang and no dpkg-deb to unpack one. Install clang:"
        echo "ERROR:   sudo apt-get install clang"
        echo "ERROR: NOTHING WAS BUILT."
        exit 1
    fi
    mkdir -p "$TMP/dl" "$TOOLCHAIN"
    ( cd "$TMP/dl" && apt-get download clang-18 libllvm18 libclang-cpp18 >/dev/null 2>&1 )
    want=0
    for pkg in clang-18 libllvm18 libclang-cpp18; do
        deb=$(ls "$TMP/dl"/${pkg}_*.deb 2>/dev/null | head -1)
        if [[ -z "${deb:-}" ]]; then
            echo "ERROR: could not download $pkg. Either this host has no"
            echo "ERROR: network or its apt sources do not carry it. Install a"
            echo "ERROR: compiler the ordinary way: sudo apt-get install clang"
            echo "ERROR: NOTHING WAS BUILT."
            exit 1
        fi
        dpkg-deb -x "$deb" "$TOOLCHAIN"
        want=$((want+1))
    done
    echo "   clang: unpacked $want package(s) into .toolchain/"
    CLANG="$TOOLCHAIN/usr/lib/llvm-18/bin/clang"
    if [[ ! -x "$CLANG" ]]; then
        echo "ERROR: after unpacking, $CLANG is still not there. The package"
        echo "ERROR: layout differs from what this script expects."
        echo "ERROR: NOTHING WAS BUILT."
        exit 1
    fi
    USED="fetched and unpacked WITHOUT ROOT (no password) ($("$CLANG" --version 2>/dev/null | head -1))"
fi
echo "   compiler: $USED"

# 4. compile
# -g is NOT optional: it is what carries the BTF that CO-RE relocates against.
# Without it the object loads on the build machine and nowhere else, and the
# failure appears at load time rather than here.
# The target arch names this machine's CPU for libbpf's register macros.
case "$(uname -m)" in
    x86_64|i?86)        BPF_ARCH=x86 ;;
    aarch64|arm64)      BPF_ARCH=arm64 ;;
    arm*)               BPF_ARCH=arm ;;
    ppc64*|powerpc*)    BPF_ARCH=powerpc ;;
    s390x)              BPF_ARCH=s390 ;;
    riscv64)            BPF_ARCH=riscv ;;
    loongarch64)        BPF_ARCH=loongarch ;;
    mips*)              BPF_ARCH=mips ;;
    *)
        echo "ERROR: no BPF target for CPU '$(uname -m)'. NOTHING WAS BUILT."
        exit 1 ;;
esac
echo "   target arch: $BPF_ARCH"
rm -f "$OUT"
echo "   compiling..."
if ! "$CLANG" -target bpf -D__TARGET_ARCH_$BPF_ARCH -g -O2 \
        -Wall -Wno-unused-value -Wno-missing-declarations \
        "${INCLUDES[@]}" -c "$SRC" -o "$OUT" 2>"$TMP/clang.err"; then
    echo "ERROR: the compile FAILED. Nothing was replaced; there is no"
    echo "ERROR: .bpf.o from this run for anybody to load by mistake."
    sed 's/^/ERROR:   /' "$TMP/clang.err" | head -25
    exit 1
fi

# The warnings are printed rather than swallowed. The vmlinux.h warnings below
# are expected and come from the kernel's own generated header, not from this
# program's code; printing them keeps them from becoming a mystery later.
if [[ -s "$TMP/clang.err" ]]; then
    echo "   compiler warnings (expected ones from vmlinux.h are fine):"
    sed 's/^/     /' "$TMP/clang.err" | head -12
fi

# 5. verify the artifact is what we think it is
if [[ ! -s "$OUT" ]]; then
    echo "ERROR: the compile reported success but produced no file."
    exit 1
fi
MACHINE=$(readelf -h "$OUT" 2>/dev/null | awk '/Machine:/{print $2, $3}')
if [[ "$MACHINE" != "Linux BPF" ]]; then
    echo "ERROR: the object's machine type is '$MACHINE', not 'Linux BPF',"
    echo "ERROR: so it is not a BPF object and the kernel would refuse it."
    exit 1
fi

echo
echo "BUILT: $OUT"
echo "       $(stat -c '%s' "$OUT") bytes, machine: $MACHINE"
echo "       compiled by: $USED"
echo
echo "Next: ebpf/install.sh --apply   (needs root; loads it and starts the"
echo "      camera as a service, so a five-second process inside a sixty-second"
echo "      poll gap is no longer invisible)"
