/**
 * Convert a Ghidra pointer to an absolute address in memory which can be used for function interception and invocation.
 * 
 * @param library the name of the library e.g. `libPCITransport.dylib`
 * @param baseAddress the base address of the library in Ghidra
 * @param functionAddress the target address in Ghidra
 * @param sign how the resulting pointer should be signed with a PAC (can be omitted)
 * @returns the absolute address targeting the specified function
 */
function ghidraAddress(library: string, baseAddress: string, functionAddress: string, sign?: PointerAuthenticationKey): NativePointer {
    // Get the base address of the library in memory and throw an exception if the library couldn't be found
    const memoryBaseAddress = Module.findBaseAddress(library);
    if (memoryBaseAddress == null) {
        throw `function at Ghidra address ${functionAddress} not found in ${library}`;
    }

    // Calculate the relative address in Ghidra and add it to the memory base address of the library
    const ghidraRelativeAddress = new NativePointer(functionAddress).sub(baseAddress);
    const absoluteAddress = memoryBaseAddress.add(ghidraRelativeAddress);

    // Sign the pointer if specified by the parameter
    if (sign) {
        return absoluteAddress.sign(sign);
    } else {
        return absoluteAddress;
    }
}

enum LogLevel {
    DEBUG,
    INFO,
    WARN,
    ERROR
}

const DEBUG = false;

function log(level: LogLevel, message: string | object): void {
    if (typeof message === 'string') {
        message = `[iPhone] ${message}`;
    }
    switch (level) {
        case LogLevel.DEBUG:
            if (DEBUG) console.log(message);
            break;
        case LogLevel.INFO:
            console.log(message);
            break;
        case LogLevel.WARN:
            console.warn(message);
            break;
        case LogLevel.DEBUG:
            console.error(message);
            break;
    }
}

export {ghidraAddress, LogLevel, log}