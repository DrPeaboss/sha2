# SHA2 for Pascal

SHA2 algorithm implemented by Pascal.

It contains `SHA224`, `SHA256`, `SHA384`, `SHA512`, `SHA512/224`, `SHA512/256`.

You can find SHA2 standard [here](https://csrc.nist.gov/publications/detail/fips/180/4/final).

## Highlights

- For free pascal, it does not have SHA2 unit, so you can use this to add it.

- For delphi, this code's performance is better than codes in `System.Hash`.

- The SHA256 part have specialized optimization assembler code for i386(basic instruction set).

## How to use

Copy files in `source` directory to the place you like or add it to search path.

You can find some demos in `demos` directory.

## Help

If you have faster codes, just show it.
