# iPhone QMI Wireshark

Dissect QMI packets sent to and received by a iPhone Qualcomm baseband chip. 

Heavily inspired by [seemoo-lab/aristoteles](https://github.com/seemoo-lab/aristoteles/blob/master/tools/watch_frida.py).

## Setup

### Install the QMI Dissector

Install the dissector by following the steps in the [dissector's README.md](./dissector)

### Install Requirements for Monitoring Packets
First, build the Frida agent using
```bash
npm install
npm run build
```

Then, install the required Python packages
```bash
# If you've installed Python via homebrew on macOS, use `brew install pipenv`
pip install pipenv
# Install required Python packages using pipenv
pipenv sync
```

Next, install libimobiledevice by following their [instructions](https://libimobiledevice.org/#downloads).

### Install Baseband Profile

Install the developer profile *Baseband for iOS* available from 
[Apple](https://developer.apple.com/bug-reporting/profiles-and-logs/?name=baseband) on your target device.

This is especially important for monitoring packets using idevicesyslog.

## Usage
### Monitor Live QMI Packets

```bash
# On jailbroken devices (using Frida)
pipenv run python3 watch_frida.py
# On non-jailbroken devices (using idevicesyslog)
pipenv run python3 watch_syslog.py
```

### Read QMI packets from Sysdiagnose

You can import QMI packets from an iOS system diagnose.

First, create a sysdiagnose on your iPhone by following the steps laid out in the 
[instructions for the baseband debug profile](https://download.developer.apple.com/iOS/iOS_Logs/Baseband_Logging_Instructions.pdf).

Copy the `sysdiagnose_<...>.tar.gz` file to your Mac and extract it.
Inside you'll find a `system_logs.logarchive` file.
Its path is the argument required for the tool.

If you are not a Mac, you have to install additional tooling.
First install the [Rust toolchain](https://www.rust-lang.org/learn/get-started) on your system.
Then, you can compile the library [macos-unifiedlogs](https://github.com/mandiant/macos-UnifiedLogs/blob/main/BUILDING.md).
```bash
# Install Rust (on UNIX-like systems)
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
# Clone the library
cd logarchive
# Build the library
cargo build --release
```

```bash
# Import the QMI packets from the specified sysdiagnose into Wireshark (Mac)
pipenv run python3 watch_logarchive.py \
 -f ./sysdiagnose_2022.10.19_13-05-32+0200_iPhone_OS_iPhone_16H71/system_logs.logarchive
 
# Import the QMI packets from the specified sysdiagnose into Wireshark (Mac & macOS-UnifiedLogs)
pipenv run python3 watch_logarchive.py \
 -f ./sysdiagnose_2022.10.19_13-05-32+0200_iPhone_OS_iPhone_16H71/system_logs.logarchive \
 -p
 
# Import the QMI packets from the specified sysdiagnose into Wireshark (Linux & macOS-UnifiedLogs)
pipenv run python3 watch_logarchive.py \
 -f ./sysdiagnose_2022.10.19_13-05-32+0200_iPhone_OS_iPhone_16H71/system_logs.logarchive
```

### Read QMI packets from CellGuard Exports

You can export packets collected by the CellGuard iOS app into a `.cells` file.
Our script reads this file and imports its QMI packets into Wireshark. 

```bash
# Import all packets collected within the given time period 
pipenv run python3 watch_cellguard.py \
 -f ./export-2024-06-12_16-50-25.cells2 \
 --start 1686780000 \
 --end 1686823200
```
