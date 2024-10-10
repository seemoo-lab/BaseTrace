// Extracts QMI message ID using references to the function qmi::MessageBase::validateMsgId or related constructors.
// Point your cursor to the entry point of the function in the respective library and run this script.
// The function is also known as "__auth_stubs::__ZN3qmi11MessageBase13validateMsgIdEt".
// You can also point your cursor to a label referencing to the function, even if the label is unresolved.
//
// Some constructor functions of MessageBase and MutableMessageBase are also supported:
//
// qmi::MessageBase::MessageBase(MessageBase *this, ushort message_id, Error error) ->
// "__ZN3qmi11MessageBaseC1EtNS_5ErrorE", "__ZN3qmi11MessageBaseC2EtNS_5ErrorE"
//
// qmi::MutableMessageBase::MutableMessageBase(MutableMessageBase *this, ushort message_id) ->
// "__ZN3qmi18MutableMessageBaseC1Et", "__ZN3qmi18MutableMessageBaseC2Et"
//
// To show hexadecimal message IDs, right-click on the Message ID column -> Column Setting -> Format -> hex.
//
// Locate the reference using the scalar 0x1201 in libCommCenterMCommandDrivers.dylib.
//
// @author: Lukas Arnold
// @category: QMI

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import ghidra.util.exception.CancelledException;
import utils.CursorLocation;
import utils.FunctionNames;
import utils.InstructionUtils;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;

public class ExtractQMIMessageIDs extends GhidraScript {

    private static final List<String> messageStrings = List.of("SendProxy", "qmi8Response");
    private static final List<String> indicationStrings = List.of("setIndHandler", "registerUnsolicitedHandler", "qmi10Indication");

    @Override
    protected void run() throws Exception {
        // Check where the cursor is located to correctly identify the reference target address
        println("Class of currentLocation: " + currentLocation.getClass().getName());
        Address targetLocation = CursorLocation.findLocation(currentLocation, currentAddress);

        // Get all references to current address
        Reference[] references = getReferencesTo(targetLocation);

        // Check if we've got any results at all
        if (references.length == 0) {
            println("No references to the selected instruction found. Is your pointer correct?");
            return;
        }

        println("Collecting all message identifiers based on references to " + targetLocation);
        println("Found " + references.length + " references");

        ExtractionMethod extractionMethod = determineExtractionMethod(targetLocation);
        println("Uses extraction techniques for the method " + extractionMethod);

        // Build an output table
        String title = "QMI Message IDs (Found " + references.length + ")";
        TableChooserDialog table = createTableChooserDialog(title, new TableChooserExecutor() {
            @Override
            public String getButtonName() {
                return "NOP";
            }

            @Override
            public boolean execute(AddressableRowObject rowObject) {
                return false;
            }
        });

        table.addCustomColumn(new StringColumnDisplay() {
            @Override
            public String getColumnValue(AddressableRowObject rowObject) {
                return ((QMIReference) rowObject).functionName;
            }

            @Override
            public String getColumnName() {
                return "Function";
            }
        });

        table.addCustomColumn(new StringColumnDisplay() {
            @Override
            public String getColumnValue(AddressableRowObject rowObject) {
                Function function = ((QMIReference) rowObject).function;
                return function != null ? function.getName(true) : "";
            }

            @Override
            public String getColumnName() {
                return "Function Name";
            }
        });

        table.addCustomColumn(new AbstractComparableColumnDisplay<Long>() {
            @Override
            public Long getColumnValue(AddressableRowObject rowObject) {
                return ((QMIReference) rowObject).messageId;
            }

            @Override
            public String getColumnName() {
                return "Message ID";
            }
        });

        table.addCustomColumn(new StringColumnDisplay() {
            @Override
            public String getColumnValue(AddressableRowObject rowObject) {
                return ((QMIReference) rowObject).getType();
            }

            @Override
            public String getColumnName() {
                return "Type";
            }
        });

        // TODO: Search function after validateMsgId for bl getTLV and extract TLV names (but no there in all cases)

        // Convert all references and add them to the table
        Stream.of(references)
                .map(reference -> extractMessageId(reference, extractionMethod))
                .forEach(table::add);

        table.show();
    }

    /**
     * Determines the method which the extraction is based using the selected label or user input.
     *
     * @param targetLocation the location in the hex file selected by Ghidra
     * @return the method the extraction is based
     * @throws CancelledException if the user abort the user input
     */
    private ExtractionMethod determineExtractionMethod(Address targetLocation) throws CancelledException {
        // Gets the name of the currently selected location in hex code
        String functionName = FunctionNames.getUnderscoreSymbol(targetLocation, currentProgram);

        // Checks if the extraction method can be determined automatically using the stored labels
        if (functionName != null) {
            for (ExtractionMethod method : ExtractionMethod.values()) {
                for (String labelName : method.getLabelNames()) {
                    if (labelName.equals(functionName)) {
                        return method;
                    }
                }
            }
        }

        // If not, ask the user
        return askChoice("Select Extraction Method",
                "Choose the method whose label you've selected:",
                Arrays.asList(ExtractionMethod.values()),
                ExtractionMethod.MESSAGE_BASE_VALIDATE_MSG_ID);
    }

    /**
     * Tries to extract the message identifier for the source of a given reference.
     *
     * @param reference the reference to the source address
     * @return the annotated reference
     */
    private QMIReference extractMessageId(Reference reference, ExtractionMethod extractionMethod) {
        // Get the function name the reference source belongs to
        Function function = getFunctionBefore(reference.getFromAddress());
        if (function == null)
            return new QMIReference(reference, false, null, "", 0);

        // Try to determine the best function name for this function
        String functionName = FunctionNames.extractFullFunctionName(function, this);

        // Get the instruction before the reference source to find the message id
        Instruction instruction = getInstructionBefore(reference.getFromAddress());
        if (instruction == null || !instruction.getMnemonicString().equals("mov"))
            return new QMIReference(reference, false, null, "", 0);

        // Check that an instruction was found, has at least two operands, and is a "mov" operations
        return InstructionUtils.extractConstantParameter(instruction, "w1", 1)
                .map(messageId -> new QMIReference(reference, true, function, functionName, messageId))
                .orElseGet(() -> new QMIReference(reference, false, function, functionName, 0));
    }

    public record QMIReference(
            Reference reference, boolean resolved, Function function, String functionName, long messageId
    ) implements AddressableRowObject {
        @Override
        public Address getAddress() {
            return reference.getFromAddress();
        }

        /**
         * Extracts the type of QMI message (message or indication) by inspecting the function's name.
         *
         * @return type of QMI message as a string
         */
        public String getType() {
            for (String msgString : messageStrings) {
                if (functionName.contains(msgString)) return "Message";
            }
            for (String indString : indicationStrings) {
                if (functionName.contains(indString)) return "Indication";
            }
            return null;
        }
    }

    public enum ExtractionMethod {
        MESSAGE_BASE_VALIDATE_MSG_ID(
                "qmi::MessageBase::validateMsgId(MessageBase *this, ushort message_id)",
                List.of("__ZN3qmi11MessageBase13validateMsgIdEt")),
        MESSAGE_BASE_CONSTRUCTOR(
                "qmi::MessageBase::MessageBase(MessageBase *this, ushort message_id, Error error)",
                Arrays.asList("__ZN3qmi11MessageBaseC1EtNS_5ErrorE", "__ZN3qmi11MessageBaseC2EtNS_5ErrorE")),
        MUTABLE_MESSAGE_BASE_CONSTRUCTOR(
                "qmi::MutableMessageBase::MutableMessageBase(MutableMessageBase *this, ushort message_id)",
                Arrays.asList("__ZN3qmi18MutableMessageBaseC1Et", "__ZN3qmi18MutableMessageBaseC2Et")),
        ;

        private final String methodName;
        private final List<String> labelNames;

        ExtractionMethod(String methodName, List<String> labelNames) {
            this.methodName = methodName;
            this.labelNames = labelNames;
        }

        public String getMethodName() {
            return methodName;
        }

        public List<String> getLabelNames() {
            return labelNames;
        }

        @Override
        public String toString() {
            return methodName;
        }
    }

    public record CallLevel(Function function, int level) {

    }

}
