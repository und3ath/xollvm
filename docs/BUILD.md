# Building xollvm

xollvm ships three ways from one source tree, with **no edits to any LLVM file**:

| Target | How | Platforms |
|---|---|---|
| **clang/opt toolchain** (obfuscator built in) | LLVM static extension (`LLVM_EXTERNAL_PROJECTS` + `LINK_INTO_TOOLS`) | Linux, Windows, macOS |
| **loadable plugin** `Obfuscator.so` | standalone build against an installed LLVM (`-fpass-plugin`) | Linux, macOS |

> **Windows note:** loadable pass plugins need the host LLVM built with
> `-DLLVM_EXPORT_SYMBOLS_FOR_PLUGINS=ON`, which the prebuilt toolchains don't ship. On Windows use
> the **static extension** (Option A) — the pass is compiled straight into `clang`/`opt`.

If you just want binaries, skip building: grab a [release](../../releases).

---

## 1. Prerequisites

Common to every build:

- **CMake ≥ 3.20**
- **Ninja** (recommended generator)
- **Python 3** (generates the AES stub bitcode header)
- A **C++17** compiler
- **git**

Mode-specific:

| Build | Also needs |
|---|---|
| Static extension (toolchain) | A checkout of **stock LLVM** (`release/22.x`) and an **external `clang`** on `PATH` (see the cycle note below) |
| Loadable plugin | An **installed LLVM 22** with CMake config + dev headers (`llvm-22-dev`) and `clang-22` |

### The external-clang requirement (static extension only)

The AES runtime stub is compiled to LLVM bitcode by `clang`. When the obfuscator is linked *into*
the tools (`LINK_INTO_TOOLS`), it **cannot** use the in-tree `clang` being built — that would form a
dependency cycle (`clang` → `LLVMExtensions` → `Obfuscator` → aes → `clang`). So the build uses a
**separate, already-installed `clang`** found on `PATH`. Any reasonably recent clang works; its
bitcode is read by the LLVM 22 you're building (LLVM reads older bitcode).

- **Linux:** `sudo apt-get install -y clang` (or `clang-NN`)
- **Windows:** `choco install llvm` (provides `C:\Program Files\LLVM\bin\clang.exe`)
- **macOS:** the Xcode/Homebrew `clang` on `PATH`

---

## 2. Static extension — full toolchain (Linux / macOS)

Builds `clang`, `opt`, etc. with the obfuscator compiled in.

```bash
# stock LLVM + xollvm side by side
git clone --depth 1 --branch release/22.x https://github.com/llvm/llvm-project
git clone https://github.com/und3ath/xollvm

sudo apt-get install -y ninja-build cmake python3 clang    # external clang for the aes stub

cmake -S llvm-project/llvm -B build -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DLLVM_ENABLE_PROJECTS="llvm;clang" \
  -DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_EH=ON \
  -DLLVM_TARGETS_TO_BUILD="X86;AArch64;ARM;RISCV" \
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_TESTS=OFF \
  -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_BUILD_BENCHMARKS=OFF \
  -DLLVM_INCLUDE_EXAMPLES=OFF \
  -DCLANG_INCLUDE_TESTS=OFF -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF \
  -DLLVM_ENABLE_ASSERTIONS=OFF \
  -DLLVM_DISTRIBUTION_COMPONENTS="clang;clang-resource-headers;opt" \
  -DLLVM_EXTERNAL_PROJECTS=Obfuscator \
  -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR="$PWD/xollvm" \
  -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON \
  -DCMAKE_INSTALL_PREFIX="$PWD/install"

# install-distribution builds ONLY the shipped components (clang, opt + their
# libs), not the ~40 other standalone llvm-* tools — a big time saving.
cmake --build build --target install-distribution
```

> Want the full toolchain (`llvm-*` tools, `lld`, …)? Drop `LLVM_DISTRIBUTION_COMPONENTS`
> and build `--target install` instead — slower and much larger.

The three obfuscator flags are the whole integration:

- `LLVM_EXTERNAL_PROJECTS=Obfuscator` — register xollvm as an external LLVM project
- `LLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR=<xollvm dir>` — where its `CMakeLists.txt` lives
- `LLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON` — statically link it into clang/opt

Trim `LLVM_TARGETS_TO_BUILD` to what you need (e.g. just `X86`) for a much faster build.

### Static extension on Windows (MSVC)

From an **x64 Native Tools** developer prompt (or after `choco install llvm ninja`):

```bat
git clone --depth 1 --branch release/22.x https://github.com/llvm/llvm-project
git clone https://github.com/und3ath/xollvm

cmake -S llvm-project\llvm -B build -G Ninja ^
  -DCMAKE_BUILD_TYPE=Release ^
  -DCMAKE_MSVC_RUNTIME_LIBRARY=MultiThreadedDLL ^
  -DLLVM_ENABLE_PROJECTS="llvm;clang" ^
  -DLLVM_ENABLE_RTTI=ON -DLLVM_ENABLE_EH=ON ^
  -DLLVM_TARGETS_TO_BUILD="X86;AArch64;ARM;RISCV" ^
  -DLLVM_INCLUDE_TESTS=OFF -DLLVM_BUILD_TESTS=OFF ^
  -DLLVM_INCLUDE_BENCHMARKS=OFF -DLLVM_BUILD_BENCHMARKS=OFF ^
  -DLLVM_INCLUDE_EXAMPLES=OFF ^
  -DCLANG_INCLUDE_TESTS=OFF -DCLANG_ENABLE_STATIC_ANALYZER=OFF -DCLANG_ENABLE_ARCMT=OFF ^
  -DLLVM_ENABLE_ASSERTIONS=OFF ^
  -DLLVM_PARALLEL_LINK_JOBS=1 ^
  -DLLVM_DISTRIBUTION_COMPONENTS="clang;clang-resource-headers;opt" ^
  -DLLVM_EXTERNAL_PROJECTS=Obfuscator ^
  -DLLVM_EXTERNAL_OBFUSCATOR_SOURCE_DIR=%CD%\xollvm ^
  -DLLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON ^
  -DCMAKE_INSTALL_PREFIX=%CD%\install

cmake --build build --target install-distribution
```

`LLVM_PARALLEL_LINK_JOBS=1` keeps peak RAM sane during the big links.

---

## 3. Loadable plugin — `Obfuscator.so` (Linux / macOS)

Builds only the pass, against an **installed** LLVM 22. No LLVM source build needed — fast.

```bash
# Ubuntu 24.04 has no clang-22/llvm-22 in its default repos; add apt.llvm.org:
wget -qO llvm.sh https://apt.llvm.org/llvm.sh && chmod +x llvm.sh && sudo ./llvm.sh 22
sudo apt-get install -y ninja-build clang-22 llvm-22 llvm-22-dev

git clone https://github.com/und3ath/xollvm
cmake -S xollvm -B build -G Ninja \
  -DLLVM_DIR=/usr/lib/llvm-22/lib/cmake/llvm \
  -DCMAKE_C_COMPILER=clang-22 -DCMAKE_CXX_COMPILER=clang++-22 \
  -DCMAKE_BUILD_TYPE=Release
ninja -C build Obfuscator            # -> build/Obfuscator.so
```

> On distros that already ship LLVM 22 (e.g. Ubuntu 26.04), the `llvm.sh` step is unnecessary —
> just `apt-get install llvm-22-dev clang-22`.

---

## 4. Verify the build

```bash
cat > ann.c <<'EOF'
#define OBF(spec) __attribute__((annotate("obf: " spec)))
OBF("mba, bcf, split")
int secret(int x){ int a=x*3+7; for(int i=0;i<x;i++) a+=(i^a); return a; }
EOF

# emit IR (any clang)
clang -O0 -emit-llvm -S ann.c -o ann.ll
```

**Static-extension toolchain** — the pass is built in, no plugin flag:

```bash
./install/bin/opt -passes=obfuscation ann.ll -S -o ann.obf.ll
./install/bin/opt -passes=verify ann.obf.ll -disable-output && echo OK
```

**Loadable plugin** — load the `.so`:

```bash
opt-22 -load-pass-plugin=./build/Obfuscator.so -passes=obfuscation ann.ll -S -o ann.obf.ll
```

`@secret` should grow substantially; an unannotated function is left untouched.

---

## 5. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| `Unable to locate package clang-22 / llvm-22-dev` | Ubuntu 24.04 default repos lack LLVM 22. Add apt.llvm.org: `sudo ./llvm.sh 22` (see §3). |
| `fatal error: aes_stub_bc.inc: No such file` | The AES stub header wasn't generated before compile. Make sure you built with the current `CMakeLists.txt` (the dependency ordering is handled by `add_dependencies(obj.Obfuscator aes_stub_inc)`). Reconfigure from clean. |
| `aes stub: external clang not found` | No `clang` on `PATH` for the stub. Install one (§1) — the in-tree clang can't be used under `LINK_INTO_TOOLS`. |
| dependency-cycle error at configure | The aes stub picked the in-tree clang. Ensure an **external** clang is found first, or that `LLVM_OBFUSCATOR_LINK_INTO_TOOLS=ON` is set so xollvm switches to the external clang automatically. |
| `-load-pass-plugin` aborts on Windows | Loadable plugins aren't supported on Windows. Use the static extension (Option A). |
| `Option '…' registered more than once` | A second copy of LLVM's global state. Don't pass `LINK_COMPONENTS` to the plugin / don't static-link LLVM into the `.so`. |

---

## 6. CI

`.github/workflows/release.yml` runs the same recipes on GitHub-hosted runners (manual trigger):
a `toolchain` matrix (Linux + Windows static-extension builds) and a `plugin` job (Linux `.so`),
then attaches all artifacts to a **draft** release. See the workflow for the exact, reproducible
flags.
