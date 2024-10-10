package utils;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Symbol;

import java.util.List;
import java.util.Optional;

public class InstructionUtils {

    public static Optional<Address> extractBranchTarget(Instruction instruction) {
        Object[] opObjects = instruction.getOpObjects(0);
        if (opObjects.length < 1)
            return Optional.empty();

        if (!(opObjects[0] instanceof Address address))
            return Optional.empty();

        return Optional.of(address);
    }

    public static List<Symbol> extractBranchTargetSymbols(Instruction instruction, Program program) {
        Object[] opObjects = instruction.getOpObjects(0);
        if (opObjects.length < 1 || !(opObjects[0] instanceof Address address)) {
            return List.of();
        }

        return List.of(program.getSymbolTable().getSymbols(address));
    }

    public static Optional<Object> extractParameter(Instruction instruction, String targetRegister, int opIndex) {
        // Check that an instruction was found
        if (instruction == null)
            return Optional.empty();

        // Check that the first operand points to the correct memory location
        if (targetRegister != null) {
            Object[] firstOpObjects = instruction.getOpObjects(0);
            if (firstOpObjects.length < 1 || !(firstOpObjects[0] instanceof Register register)) {
                return Optional.empty();
            }

            if (!register.getName().equals(targetRegister)) {
                return Optional.empty();
            }
        }

        // Check that the second or third operand exists and is a scalar
        Object[] targetOpObject = instruction.getOpObjects(opIndex);
        if (targetOpObject.length < 1) {
            return Optional.empty();
        }

        // Get the value of the scalar
        return Optional.of(targetOpObject[0]);
    }

    public static Optional<Long> extractConstantParameter(Instruction instruction, String targetRegister, int opIndex) {
        Optional<Object> o = extractParameter(instruction, targetRegister, opIndex);

        if (o.isPresent() && o.get() instanceof Scalar scalar) {
            return Optional.of(scalar.getValue());
        }

        return Optional.empty();
    }

    public static boolean compareStore(Instruction instruction, String readRegName, String targetRegName) {
        if (instruction == null)
            return false;

        if (readRegName != null) {
            Object[] opObjectsFirst = instruction.getOpObjects(0);
            if (opObjectsFirst.length < 1 || !(opObjectsFirst[0] instanceof Register readRegister)) {
                return false;
            }
            if (!readRegister.getName().equals(readRegName)) {
                return false;
            }
        }

        if (targetRegName != null) {
            Object[] opObjectsSecond = instruction.getOpObjects(1);
            if (opObjectsSecond.length < 1 || !(opObjectsSecond[0] instanceof Register targetRegister)) {
                return false;
            }
            if (!targetRegister.getName().equals(targetRegName)) {
                return false;
            }
        }

        return true;
    }

}
