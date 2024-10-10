// *** Receiving direction ***
// Air -> Chip -> iPhone

import { log, LogLevel } from "./tools";

// libATCommandStudioDynamic.dylib
// QMux::State::handleReadData(QMux::State *__hidden this, const unsigned __int8 *, unsigned int)
// -> Part of the ICEPicker repository

let lastQmux = 0;  // save the last state of x0

const handleReadData = Module.getExportByName('libATCommandStudioDynamic.dylib', '_ZN4QMux5State14handleReadDataEPKhj');
Interceptor.attach(handleReadData, {
    onEnter: function (args) {
        log(LogLevel.DEBUG, 'libATCommandStudioDynamic:QMux::State::handleReadData');

        const armContext = this.context as Arm64CpuContext;

        // x0 points to __ZTVN4QMux5StateE + 8 (QMux::State)
        // there are qmux1 and qmux2 or so, so let's keep track of that.
        const currentQmux = parseInt(armContext.x0.toString());
        if (lastQmux != currentQmux) {
            log(LogLevel.DEBUG, `qmux pointer changed: ${currentQmux}`);

            send('data', [0x23]);  // Indicate with 0x23, QMI always starts with 0x01
            lastQmux = currentQmux;
        }

        var dst = armContext.x1;
        var len = parseInt(armContext.x2.toString());
        var d = dst.readByteArray(len);
        log(LogLevel.DEBUG, d!);
        
        send('data', d);
    }
});
