# ============================================================================
# strenc AES stub build
# ============================================================================

set(_AES_STUB_SRC  "${CMAKE_CURRENT_SOURCE_DIR}/aes_stub.c")
set(_AES_BIN2C     "${CMAKE_CURRENT_SOURCE_DIR}/aes_bin2c.py")

set(_AES_STUB_BC   "${CMAKE_CURRENT_BINARY_DIR}/aes_stub.bc")
set(_AES_STUB_INC  "${CMAKE_CURRENT_BINARY_DIR}/aes_stub_bc.inc")

# ---------------------------------------------------------------------------
# Step 1: C → LLVM bitcode
# ---------------------------------------------------------------------------
add_custom_command(
  OUTPUT  "${_AES_STUB_BC}"
  COMMAND "${_AES_CLANG_EXE}"
          -O2
          -emit-llvm
          -c
          -ffreestanding
          -fno-builtin-memcpy
          -fno-builtin-memset
          -fvisibility=hidden
          -target "${AES_STUB_TARGET}"
          -fno-pic
          -g0
          "${_AES_STUB_SRC}"
          -o "${_AES_STUB_BC}"
  DEPENDS "${_AES_STUB_SRC}" ${_AES_CLANG_DEP}
  COMMENT "aes: compiling AES-CTR stub → LLVM bitcode"
  VERBATIM
)

# ---------------------------------------------------------------------------
# Step 2: Bitcode → C array
# ---------------------------------------------------------------------------
add_custom_command(
  OUTPUT  "${_AES_STUB_INC}"
  COMMAND "${Python3_EXECUTABLE}"
          "${_AES_BIN2C}"
          "${_AES_STUB_BC}"
          "${_AES_STUB_INC}"
  DEPENDS "${_AES_STUB_BC}" "${_AES_BIN2C}"
  COMMENT "aes: embedding bitcode as C array"
  VERBATIM
)


# ---------------------------------------------------------------------------
# Public target
# ---------------------------------------------------------------------------
add_custom_target(aes_stub_inc
  DEPENDS "${_AES_STUB_INC}"
)


# Export generated .inc path to parent
set(AES_GENERATED_INC
    "${_AES_STUB_INC}"
    PARENT_SCOPE)
