# SHA2 for Pascal

SHA2 algorithm implemented by Pascal.

It contains `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512/224`, `SHA512/256`.

You can find SHA2 standard [here](https://csrc.nist.gov/publications/detail/fips/180/4/final).

## Highlights

- For Free Pascal 3.2.2, it does not have SHA2 unit, so you can use this to add it.
- For Free Pascal 3.3.1, the fpsha256 and fpsha512 in fcl-hash is not optimized.
- For Delphi, the code's performance in `System.Hash` is not optimized.
- The SHA256 part have specialized optimization assembler code for i386 and x86_64(basic instruction set).
- The SHA512 part have specialized optimization assembler code for x86_64(basic instruction set).

## Benchmark

1 GiB buffer, use FPC 3.2.2 and FPC 3.3.1, optimization level 2, assembler code and pure pascal code.

CPU: AMD Ryzen 5 4600H, System: Windows 11 22H2

| FPC 3.2.2  |   i386    |  x86_64   |
| ---------- | --------- | --------- |
| SHA256 Asm | 266 MiB/s | 281 MiB/s |
| SHA256 Pas | 173 MiB/s | 230 MiB/s |
| SHA512 Asm | N/A       | 465 MiB/s |
| SHA512 Pas | 65 MiB/s  | 360 MiB/s |

| FPC 3.3.1  |   i386    |  x86_64   |
| ---------- | --------- | --------- |
| SHA256 Asm | 276 MiB/s | 299 MiB/s |
| SHA256 Pas | 145 MiB/s | 228 MiB/s |
| SHA512 Asm | N/A       | 468 MiB/s |
| SHA512 Pas | 63 MiB/s  | 365 MiB/s |

FPC 3.3.1 seems have better optimization, but the i386 pure pascal is regressed (SHA256 Pas, 173 MiB/s vs 145 MiB/s).

## How to use

Copy files in `source` directory to the place you like or add it to search path.

You can find some demos in `demos` directory.

## TODO

Use SSE2 for i386 and x86_64.
