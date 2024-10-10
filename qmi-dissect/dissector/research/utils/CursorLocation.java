package utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.program.util.LabelFieldLocation;
import ghidra.program.util.OperandFieldLocation;
import ghidra.program.util.ProgramLocation;

public class CursorLocation {

    public static Address findLocation(ProgramLocation currentLocation, Address currentAddress) {
        Address targetLocation = findSpecialLocation(currentLocation);
        // Ensure that we don't use a refAddress property which was null
        return targetLocation != null ? targetLocation : currentAddress;
    }

    private static Address findSpecialLocation(ProgramLocation currentLocation) {
        if (currentLocation instanceof LabelFieldLocation) {
            // The reference address in this case can be sometimes null
            return currentLocation.getRefAddress();
        } else if (currentLocation instanceof OperandFieldLocation) {
            // In this case the address can also be outside the allocated program space
            return currentLocation.getRefAddress();
        }

        return null;
    }

}
