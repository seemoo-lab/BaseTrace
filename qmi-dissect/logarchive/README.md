# Logarchive Parser

This is a parser for .logarchive files focused on QMI packets based on [macos-UnifiedLogs](https://github.com/mandiant/macos-UnifiedLogs).

The resulting .csv file only contains log messages related to QMI packets.

## Build

Install the [Rust toolchain](https://www.rust-lang.org/tools/install) on your system.

```sh
# Build the executable
cargo build --release
```

## Usage

```sh
# Read logarchive from a sysdiagnose into the file parsed-qmi-logarchive.csv.
# The console may show warnings or errors while running this command, however they don't affect the packet log messages.
./target/release/unifiedlog_parser -i ~/sysdiagnose_2024.04.12_11-19-45+0200_iPhone-OS_iPhone_21E236/system_logs.logarchive -o parsed-qmi-logarchive.csv
```
