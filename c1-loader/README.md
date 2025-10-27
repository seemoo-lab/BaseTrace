# Sinope Binja Loader (Rust)

A [Binary Ninja](https://binary.ninja) loader for fwsg binaries (rkos, cdpu, cdpd, l1cs, cdph, CR.., R...) part of the Apple's C1 / C4000 / Sinope baseband firmware.
The current version of the loader supports the native Rust interface of Binary Ninja v5.1.  

## Downloading & Extracting Firmware

Make sure to install blacktop's command-line utility [ipsw](https://github.com/blacktop/ipsw?tab=readme-ov-file#installation). 

```shell
# Download ftab.bin of latest iOS version for iPhone16 e (iPhone17,5)
ipsw download appledb --os iOS --latest --device "iPhone17,5" --release --pattern "c4000"
# Extract ftab.bin into extracted/
ipsw fw c1 23A355__iPhone17,5/23A355__iPhone17,5/Firmware/c4000v59/Release/patched/ftab.bin
# Open directory with extracted firmware files
open extracted
```

## Installation

```shell
cargo build --release
ln -sf $PWD/target/release/libc1_binja_loader.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins
```

## Development

```shell
# Create debug build (may be slower)
cargo build
ln -sf $PWD/target/debug/libc1_binja_loader.dylib ~/Library/Application\ Support/Binary\ Ninja/plugins
# Print Binary Ninja log to console to diagnose crashes 
/Applications/Binary\ Ninja.app/Contents/MacOS/binaryninja --debug --stderr-log
```

## References

Binary Ninja's Rust API:
- https://dev-rust.binary.ninja/binaryninja/index.html
- https://github.com/Vector35/binaryninja-api/tree/dev/rust/examples
- https://github.com/topics/binary-ninja?l=rust
- https://github.com/cxiao/minidump_bn/
- https://github.com/bdash/bn-objc-extras
- https://docs.rs/deku/latest/deku/

C4000 Firmware:
- https://theapplewiki.com/wiki/C4000
- https://github.com/nlitsme/AppleC4000
- https://gist.github.com/pwnlambda/06092d5f416dbc0a82e204b8bbc4b72c
- https://lukasarnold.de/posts/obtsv8-talk/
