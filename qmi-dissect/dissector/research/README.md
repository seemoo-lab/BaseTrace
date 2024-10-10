# QMI Research

You can discover new QMI message identifier using the tools available in this directory.
You can combine two approaches for this task.

## Background

The function `qmi::MessageBase::validateMsgId` is called by a large number of QMI message, the iPhone sends and receives.
Its two parameters are the instance pointer of the `MessageBase` object and the `message_id` as an unsigned short.

Thus, we can use it to translate previously unknown message ids to strings and better understand the communication between the iPhone application processor and its baseband processor.

## Dynamic 
The dynamic approach uses [Frida](https://frida.re) to intercept calls to the function `qmi::MessageBase::validateMsgId` from the library `libQMIParserDynamic.dylib` in real-time.
You can try different things on the iPhone to collect as much message ids as possible.
A jailbroken iPhone is required to execute the script.
It is optimized for an iPhone 12 mini with iOS 14.2.1.

```bash
frida -U -l explore_frida.ts CommCenter
```

Messages of the QMI position determination service (PDS) are handled by the `locationd` process.
Its executable can be found in `/usr/libexec/locationd`.
```bash
frida -U locationd -l explore_frida.ts
```

## Static
The static approach uses a Ghidra script to scan all references to the function `qmi::MessageBase::validateMsgId` and show respective message ids & calling functions in a table.

To use it, add this folder as a script directory in Ghidra (so it can detect the file [ExtractQMIMessageIDs.java](./ExtractQMIMessageIDs.java)), point your cursor to the entry point of the function `__auth_stubs::__ZN3qmi11MessageBase13validateMsgIdEt` in your target library and run it using the script manager. 

Good resources to learn Ghidra scripting are 
- [Ghidra Javadocs](https://ghidra.re/ghidra_docs/api/ghidra/app/script/GhidraScript.html)
- [sentinelone.com](https://www.sentinelone.com/labs/a-guide-to-ghidra-scripting-development-for-malware-researchers/)
- [HackOvert/GhidraSnippets](https://github.com/HackOvert/GhidraSnippets)
- [garyttierney/intellij-ghidra](https://github.com/garyttierney/intellij-ghidra)

### Import

Based on static approach we can automatically analyze binaries, extract their QMI definitions, and convert them to libqmi data structures which in turn can be used for improving the dissector. 

1. Get IPSW 
2. `ipsw dyld imports dyld_shared_cache_arm64e /usr/lib/libQMIParserDynamic.dylib`
3. Put each file in Ghidra
4. Apply plugin
5. Run script to import

Repeat for executables like locationd but apply symbol plugin before

## Results

The results can be used to manually improve the iOS extensions for libqmi, located in the [libqmi-ios-ext](../../../libqmi-ios-ext) directory.
