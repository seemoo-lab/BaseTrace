// *** Sending direction ***
// iPhone -> Chip -> Air

import { ghidraAddress, log, LogLevel } from "./tools";

// State required for injecting custom QMI packets
let writeAsyncState: NativePointer | null = null;

// Allocate 8 bytes of memory allowing a function to store its result
const thTargetMemory = Memory.alloc(8);

// libPCITransport.dylib!pci::system::info::get()::sInstance
const pciSystemInfoGetSInstance = ghidraAddress('libPCITransport.dylib', '0x1c8474000', '0x1dffe19f0');

// libPCITransport.dylib!pci::system::info::getTH
const pciSystemInfoGetTHAddr = ghidraAddress('libPCITransport.dylib', '0x1c8474000', '0x1c8475234', 'ia');
const pciSystemInfoGetTH = new NativeFunction(pciSystemInfoGetTHAddr, 'void', ['pointer', 'int']);

function initializeWriteParameters(): void {
    // Prepare an interceptor of the function to be invoked
    let interceptor = Interceptor.attach(pciSystemInfoGetTH, {
        // Before we enter the function, we modify the register X8
        // X8 / XR is an indirect result return register: https://developer.arm.com/documentation/102374/0100/Procedure-Call-Standard
        // It points to a memory location where the 'this' pointer (result of the function invocation) will be written 
        onEnter: function (args) {
            log(LogLevel.DEBUG, 'getTransportThis(): Interceptor: onEnter()');
            (this.context as Arm64CpuContext).x8 = thTargetMemory;
        },
        // After the function is complete, we read the 'this' pointer from the specified memory location,
        // detach the interceptor and start sending QMI packets. 
        onLeave: function (returnValue) {
            const transportThis = thTargetMemory.readPointer();
            log(LogLevel.DEBUG, `getTransportThis(): Interceptor: onLeave() with writeAsyncState = ${transportThis}`);

            // Detach the interceptor as we don't require it anymore
            interceptor.detach();

            // Save the state information and signal it to the Python script
            writeAsyncState = transportThis;
            send('setup', [0x1]);
        }
    });

    // Read the first parameter from a static location in memory
    const param1 = pciSystemInfoGetSInstance.readPointer();

    // The second parameter (0x3) is a static value found by observation
    const param2 = 0x3;

    // Invoke the function with the two parameters 
    log(LogLevel.DEBUG, `initializeWriteParameters(): pciSystemInfoGetTH(${param1}, ${param2})`);
    pciSystemInfoGetTH(param1, param2);
}

initializeWriteParameters();

// libPCITransport.dylib
// bool pci::transport::th::writeAsync(*th this, byte[] data, uint length, void (*)(callback*));
// -> Found with using https://github.com/seemoo-lab/frida-scripts/blob/main/scripts/libdispatch.js

// The maximum packet length is 0x7fff
const payloadBuffer = Memory.alloc(0x8050);

const writeAsyncAddr = ghidraAddress('libPCITransport.dylib', '0x1c8474000', '0x1c84868b4', 'ia');
const writeAsync = new NativeFunction(writeAsyncAddr, "bool", ["pointer", "pointer", "uint", "pointer"]);

// The callback function (4th parameter) used during a normal write operation points to 
// libmav_ipc_router_dynamic.dylib!mav_router::device::pci_shim::dtor
const writeAsyncCallback = Module.getExportByName('libmav_ipc_router_dynamic.dylib', '_ZN10mav_router6device8pci_shim4dtorEPv');

function injectQMI(payload: string) {
    if (!writeAsyncState || !writeAsyncCallback) {
        // TODO: Try to resend?
        console.warn("inject called although write state is not initialized");
        return
    }

    const payloadArray: number[] = [];
    const payloadLength = payload.length / 2;

    // Read hex strings from payload and convert to byte array (F4118456 -> [244 17 132 86])
    for (let i = 0; i < payload.length; i += 2) {
        payloadArray.push(parseInt(payload.substring(i, i + 2), 16));
    }

    // Write content of array to our payload buffer
    payloadBuffer.writeByteArray(payloadArray);

    log(LogLevel.DEBUG, "libPCITransport::pci::transport::th::writeAsync");
    // log(LogLevel.DEBUG, payload);
    log(LogLevel.DEBUG, payloadBuffer.readByteArray(payloadLength)!);
    log(LogLevel.DEBUG, `writeAsync: ${writeAsync}`);
    log(LogLevel.DEBUG, `writeAsyncState: ${writeAsyncState}`);
    log(LogLevel.DEBUG, `payloadBuffer: ${payloadBuffer}`);
    log(LogLevel.DEBUG, `payloadLength: ${payloadLength}`);
    log(LogLevel.DEBUG, `writeAsyncCallback: ${writeAsyncCallback}`);
    log(LogLevel.DEBUG, '');

    // Call the function writeAsync with the correct state and payload
    // For now we ignore the writeAsyncCallback as it blocks a write operation and it works perfectly fine without it :)
    writeAsync(writeAsyncState, payloadBuffer, payloadLength, new NativePointer("0x0"));
}

export { injectQMI }