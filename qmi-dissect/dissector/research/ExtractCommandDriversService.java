// Associates QMI Command Drivers with their respective QMI Service.
// Point your 'QMIClientPool::requestClient'
//
// Locate the reference using the scalar 0xEA in libCommCenterMCommandDrivers.dylib in the QMIStewieCommandDriver.
//
// @author: Lukas Arnold
// @category: QMI

import ghidra.app.script.GhidraScript;
import ghidra.app.tablechooser.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.symbol.Reference;
import utils.CursorLocation;
import utils.InstructionUtils;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Optional;
import java.util.stream.Stream;

public class ExtractCommandDriversService extends GhidraScript {

    @Override
    protected void run() throws Exception {
        // TODO: Check that the correct method is selected

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

        println("Collecting command drivers based on references to " + targetLocation);
        println("Found " + references.length + " references");

        // Build an output table
        String title = "QMI Services used by Command Drivers (Found " + references.length + ")";
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
                return ((CommandDriverReference) rowObject).driverName;
            }

            @Override
            public String getColumnName() {
                return "Driver Name";
            }
        });

        table.addCustomColumn(new AbstractComparableColumnDisplay<Long>() {
            @Override
            public Long getColumnValue(AddressableRowObject rowObject) {
                return ((CommandDriverReference) rowObject).serviceId;
            }

            @Override
            public String getColumnName() {
                return "QMI Service";
            }
        });

        // Convert all references and add them to the table
        Stream.of(references)
                .map(this::extractServiceId)
                .forEach(table::add);

        table.show();
    }

    /**
     * Tries to extract the QMI service for the source of a given reference.
     *
     * @param reference the reference to the source address
     * @return the annotated reference
     */
    private CommandDriverReference extractServiceId(Reference reference) {
        // Get the function name the reference source belongs to
        Function function = getFunctionBefore(reference.getFromAddress());
        if (function == null)
            return new CommandDriverReference(reference, null, "", -1);

        // Extract the full function name starting with '__' as it exposes more information about a given function
        // String functionName = FunctionNames.extractFullFunctionName(function, this);
        String driverName = extractDriverName(function);

        // Get the instruction before the reference source to find the message id
        Instruction instruction = getInstructionBefore(reference.getFromAddress());

        // Check 4 previous instructions if they provide us with the value in question
        for (int i = 0; i < 4; i++) {
            if (instruction == null) break;

            if (instruction.getMnemonicString().equals("mov")) {
                Optional<Long> serviceId = InstructionUtils.extractConstantParameter(instruction, "w1", 1);

                // Check if we've found the right instruction and if yes return
                if (serviceId.isPresent()) {
                    return new CommandDriverReference(reference, function, driverName, serviceId.get());
                }
            }

            // Get the instruction before the current one
            instruction = instruction.getPrevious();
        }

        // We didn't find the correct instruction
        return new CommandDriverReference(reference, function, driverName, -1);
    }

    private String extractDriverName(Function function) {
        String functionName = function.getName(true);

        if (functionName.startsWith("dispatch")) {
            // Extract the crucial information from the long dispatch name
            String[] splitOne = functionName.split("dispatch::async<ctu::SharedSynchronizable<", 2);
            if (splitOne.length < 2) {
                return functionName;
            }
            String[] splitTwo = splitOne[1].split(">", 2);
            if (splitTwo.length < 2) {
                return splitOne[1];
            }
            return splitTwo[0];
        } else {
            // Remove the last method but keep other prefixes
            List<String> split = new ArrayList<String>(Arrays.asList(functionName.split("::")));
            split.removeLast();
            return String.join("::", split);
        }
    }

    public record CommandDriverReference(
            Reference reference, Function function, String driverName, long serviceId
    ) implements AddressableRowObject {
        @Override
        public Address getAddress() {
            return reference.getFromAddress();
        }

        public boolean isResolved() {
            return serviceId > 0;
        }
    }

}
