#!/usr/bin/env python3
import sys
import os


def main() -> int:
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.bc> <output.inc>", file=sys.stderr)
        return 1

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    if not os.path.isfile(input_path):
        print(f"Error: file not found: {input_path}", file=sys.stderr)
        return 1

    with open(input_path, "rb") as f:
        data = f.read()

    if not data:
        print("Error: input file is empty", file=sys.stderr)
        return 1

    cols = 16

    with open(output_path, "w", newline="\n") as out:
        for i in range(0, len(data), cols):
            chunk = data[i:i + cols]
            hex_vals = ", ".join(f"0x{b:02x}" for b in chunk)
            out.write(f"    {hex_vals},\n")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
