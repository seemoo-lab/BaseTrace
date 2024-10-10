import { ghidraAddress, log, LogLevel } from "./tools";

// *** Sending direction ***
// iPhone -> Chip -> Air

// libPCITransport.dylib
// bool pci::transport::th::writeAsync(*th this, byte[] data, uint length, void (*)(callback*));
// -> Found with using https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js

const writeAsyncAddr = ghidraAddress('libPCITransport.dylib', '0x1c8474000', '0x1c84868b4', 'ia');

Interceptor.attach(writeAsyncAddr, {
    onEnter: function(args) {
        const state = args[0];
        const buffer = args[1];
        const length = args[2];
        const callback = args[3];

        const bufferData = buffer.readByteArray(parseInt(length.toString()));

        log(LogLevel.DEBUG, "libPCITransport::pci::transport::th::writeAsync (onEnter)");
        log(LogLevel.DEBUG, `writeAsync: ${writeAsyncAddr}`);
        log(LogLevel.DEBUG, `x0: writeAsyncState: ${state}`);
        log(LogLevel.DEBUG, `x1: payloadBuffer: ${buffer}`);
        log(LogLevel.DEBUG, bufferData!);
        log(LogLevel.DEBUG, `x2: payloadLength: ${length}`);
        log(LogLevel.DEBUG, `x3: writeAsyncCallback: ${callback}`);
        log(LogLevel.DEBUG, ` -> ${DebugSymbol.fromAddress(callback)}`);
        log(LogLevel.DEBUG, '');

        send('qmi_send', bufferData);
    },
    onLeave: function(returnValue) {
        log(LogLevel.DEBUG, "libPCITransport::pci::transport::th::writeAsync (onLeave)");
        log(LogLevel.DEBUG, `Return Value: ${returnValue}`);
        log(LogLevel.DEBUG, '');
    }
});
