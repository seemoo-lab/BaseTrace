/// <reference path="../../node_modules/@types/frida-gum/index.d.ts" />

// Library: libQMIParserDynamic.dylib
// @ts-ignore
const libraryName = "libQMIParserDynamic.dylib"

function listenCallback(functionName: string, argumentNames: string[]): InvocationListenerCallbacks {
    return {
        onEnter: function (args) {
            console.log(`${libraryName}:${functionName} (onEnter)`);

            // Print all arguments with their names
            for (let i = 0; i < argumentNames.length; i++) {
                console.log(`${argumentNames[i]}: ${args[i]}`);
            }

            // Print the backtrace causing the call of the initial instruction
            console.log('Backtrace:' +
                Thread.backtrace(this.context, Backtracer.ACCURATE)
                    .map(DebugSymbol.fromAddress).join('\n'));

            console.log('');
        },
        onLeave: function (returnValue) {
            console.log(`${libraryName}:${functionName} (onLeave)`);

            // Print the return value
            console.log(`Return Value: ${returnValue}`);

            console.log('');
        }
    }
}

// Function: qmi::MessageBase::validateMsgId
Interceptor.attach(
    Module.findExportByName('libQMIParserDynamic.dylib', '_ZN3qmi11MessageBase13validateMsgIdEt')!,
    listenCallback(
        'qmi::MessageBase::validateMessageID',
        ['MessageBase (this)', 'message_id']
    )
);

// Function: qmi::MessageBase::MessageBase (constructor)
Interceptor.attach(
    Module.findExportByName('libQMIParserDynamic.dylib', '_ZN3qmi11MessageBaseC1EtNS_5ErrorE')!,
    listenCallback(
        'qmi::MessageBase::MessageBase',
        ['MessageBase (this)', 'message_id', 'error']
    )
);

// Function: qmi::MutableMessageBase::MutableMessageBase (constructor)
Interceptor.attach(
    Module.findExportByName('libQMIParserDynamic.dylib', '_ZN3qmi18MutableMessageBaseC2Et')!,
    listenCallback(
        'qmi::MutableMessageBase::MutableMessageBase',
        ['MessageBase (this)', 'message_id']
    )
);
