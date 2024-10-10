/// <reference path="../../node_modules/@types/frida-gum/index.d.ts" />

// @ts-ignore
const libraryName = "libQMIParserDynamic.dylib"

function interceptMessageId(matches: ApiResolverMatch[]) {
    // Hook each match
    for (let match of matches) {
        Interceptor.attach(match.address, {
            onEnter: function (args) {
                // Store the first argument which is a reference to the object itself
                this.objectPointer = args[0];
            },
            onLeave: function (retval) {
                // Read the message id from the object (stored at the beginning) after the constructor has finished
                const pointer: NativePointer = this.objectPointer
                const msgId = pointer.readUShort()
                console.log(`${match.name} -> 0x${msgId.toString(16)}`);
            }
        })
    }
}

// Hook into all constructors of MessageBase or MutableMessageBase
interceptMessageId(new ApiResolver('module').enumerateMatches(`exports:${libraryName}!*MessageBaseC*`))
