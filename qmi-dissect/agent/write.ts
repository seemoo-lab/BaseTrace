import { log, LogLevel } from "./tools";

// *** Receiving direction ***
// Air -> Chip -> iPhone

// libATCommandStudioDynamic.dylib
// QMux::State::handleReadData(QMux::State *__hidden this, const unsigned __int8 *, unsigned int)
// -> Part of the ICEPicker repository

const handleReadData = Module.getExportByName('libATCommandStudioDynamic.dylib', '_ZN4QMux5State14handleReadDataEPKhj');

Interceptor.attach(handleReadData, {
    onEnter: function (args) {
        const state = args[0];
        const buffer = args[1];
        const length = args[2];

        const bufferData = buffer.readByteArray(parseInt(length.toString()));

        log(LogLevel.DEBUG, "libATCommandStudioDynamic:QMux::State::handleReadData (onEnter)");
        log(LogLevel.DEBUG, `handleReadData: ${handleReadData}`);
        log(LogLevel.DEBUG, `x0: writeAsyncState: ${state}`);
        log(LogLevel.DEBUG, `x1: payloadBuffer: ${buffer}`);
        log(LogLevel.DEBUG, bufferData!);
        log(LogLevel.DEBUG, `x2: payloadLength: ${length}`);
        log(LogLevel.DEBUG, '');
        
        send('qmi_read', bufferData);
    },
    onLeave: function(returnValue) {
        log(LogLevel.DEBUG, "libATCommandStudioDynamic:QMux::State::handleReadData (onLeave)");
        log(LogLevel.DEBUG, `Return Value: ${returnValue}`);
        log(LogLevel.DEBUG, '');
    }
});
