package utils;

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.Symbol;

import java.util.LinkedList;

public class FunctionNames {

    /**
     * Tries to determine the best available 'underscore' function name for the given function.
     * As this name exposes the most amount of information about the function.
     * This function also tries to resolve unnamed functions (which names start with FUN_)
     * by going up in the call hierarchy.
     *
     * @param function the function to search the name for
     * @param script   the instance of the script for logging & the current program
     * @return the best-possible function name for the function
     */
    public static String extractFullFunctionName(Function function, GhidraScript script) {
        String functionName = function.getName(true);

        // Try to resolve unnamed functions (which names start with FUN_) by looking up in the call hierarchy
        // or boring function names.
        if (functionName.startsWith("FUN_")) {
            String nameFromCallers = findNameFromCallers(function);
            if (nameFromCallers != null) {
                return nameFromCallers;
            }
        }

        // If the function's name is already in the underscore format, we can return it.
        if (functionName.startsWith("__") && !functionName.equals("__invoke")) {
            return functionName;
        }

        // If not, we'll try to get its underscore representation.
        if (function.getEntryPoint() != null) {
            String underscoreFunctionName = getUnderscoreSymbol(function.getEntryPoint(), script.getCurrentProgram());
            if (underscoreFunctionName != null) {
                return underscoreFunctionName;
            }
        } else {
            script.println("Entry Point of function is null: " + function.getName(true));
        }

        // If nothing of our approaches helped to improve the function name, we just return it as is.
        return functionName;
    }

    /**
     * Tries to resolve unnamed functions (which names start with FUN_) by following the call hierarchy.
     * <p>
     * This approach is useful for binaries without symbols like 'locationd'.
     * To annotate those binaries with some names, it's important to run the ExtractDebugFunctionNames beforehand.
     * <p>
     * We perform this search up until a depth of 6 levels.
     *
     * @param firstFunction the function to analyze
     * @return the name of a function in the hierarchy or null if no better name could be found
     */
    public static String findNameFromCallers(Function firstFunction) {
        LinkedList<CallLevel> queue = new LinkedList<>();

        // Add all references to the function to the queue with level zero.
        for (Function callingFunction : firstFunction.getCallingFunctions(null)) {
            queue.offer(new CallLevel(callingFunction, 0));
        }

        // Loop while there are references to search
        while (!queue.isEmpty()) {
            // Get the first element from the queue
            CallLevel callLevel = queue.poll();

            // Check if the function has is named and if yes, return its name combined with its namespace.
            String name = callLevel.function.getName();
            String namespace = callLevel.function.getParentNamespace().getName();
            if (!name.startsWith("FUN_") && !name.startsWith("thunk_FUN_")) {
                return namespace + "::" + name;
            }

            // Don't continue searching after six levels of call hierarchy.
            if (callLevel.level >= 6) {
                continue;
            }

            // Add all references to this function to the queue with the level increased by one.
            for (Function callingFunction : callLevel.function.getCallingFunctions(null)) {
                queue.offer(new CallLevel(callingFunction, callLevel.level + 1));
            }
        }

        // If no better name has been found, return null.
        return null;
    }

    public record CallLevel(Function function, int level) {
    }

    /**
     * Searches a symbol starting with two underscores for the given address.
     * Null is returned if non can be found.
     *
     * @param address the address
     * @return the symbol name for the address starting with two underscores or null if non can be found
     */
    public static String getUnderscoreSymbol(Address address, Program program) {
        Symbol[] symbols = program.getSymbolTable().getSymbols(address);
        for (Symbol symbol : symbols) {
            if (symbol.getName().startsWith("__") && !symbol.getName().equals("__invoke")) {
                return symbol.getName();
            }
        }

        return null;
    }
}
