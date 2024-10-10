# iPhone QMI Glue

The *glue* acts a connection layer between libqmi and the baseband processor of a smartphone.

## Supported devices

We've tested this tooling with an iPhone 12 mini on iOS 14.2.1.

You may have to adapt the method signatures for subsequent iOS versions. 

## Setup

Due to the build requirements of libqmi, you must use a Linux-based operating system.
We recommend [Debian 11](https://www.debian.org/download) which you can either use as your host operating system or as a virtual machine with a shared network. This is the default setting if you're creating a VM with [UTM](https://mac.getutm.app) on a Mac.

Install [Node.js for your system](https://github.com/nodesource/distributions/blob/master/README.md), the example script is built for Debian:
```bash
./scripts/install-nodejs.sh
```

You can usually install Frida via pip:
```bash
pip install frida-tools
```
If there's an error, you can try to build & install Frida yourself using the provided script:
```bash
./scripts/install-frida.sh
```

On all systems, you must install at least version 1.33.3 of libqmi. To build libqmi, you can use the provided script:
```bash
./scripts/install-libqmi.sh
```

## Usage

## Smartphone

1. Jailbreak the target smartphone:
    - iPhone 12 (mini) with iOS 14.2.1: [unc0ver (TrollStore)](https://ios.cfw.guide/installing-unc0ver-trollstore/)
2. Install [Frida using Cydia](https://frida.re/docs/ios/).

## glue

First compile the agent script with
```bash
npm install
npm run build
```

### Linux-based host OS

If you are running the Linux-based operating system as your host system, you can start the glue application with
```bash
python3 glue.py -U
```

### VM

If you are running the Linux-based operating system inside of a VM, you must relay the Frida TCP port [27042](https://github.com/frida/frida/issues/70#issuecomment-186019188) to the VM.
1. Install [libimobiledevice](https://libimobiledevice.org) on the host system:
    - Mac with [homebrew](https://brew.sh): `brew install libimobiledevice`
2. Find the IP address of your host system inside the shared network with the VM: `ifconfig` or `ip a`
    - Mac with UTM: `192.168.64.1`, which we'll use from now on as an example, replace it if you're host system has another address in the shared network
3. Make the port available in the shared network: `iproxy 27042:27042 -s 192.168.64.1`

Now you can start the glue application:
```bash
python3 glue.py -H 192.168.64.1
```

## Test

Use qmicli on your Linux-based OS to test if everything works:
```bash
qmicli -v -d ./qmux_socket --get-service-version-info
```
Between all the packet data, you should see a list of QMI services and not an error.
