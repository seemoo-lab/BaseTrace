// Extracts C++ class and function names from debug strings.
// This script is intended for the 'locationd' binary, but could also be applied to other binaries without symbols.
//
// @author: Lukas Arnold
// @category: QMI

import ghidra.app.script.GhidraScript;
import ghidra.app.util.NamespaceUtils;
import ghidra.app.util.XReferenceUtils;
import ghidra.program.model.listing.CircularDependencyException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.util.DefinedDataIterator;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class ExtractDebugFunctionNames extends GhidraScript {

    private static final Pattern CLASS_FUNCTION_PATTERN = Pattern.compile("(\\w+)::(\\w+)");

    // We could also create a regular expression for "#bb.e" debug messages,
    // but they do not directly refer to the class and
    // should be handled with a lower priority than class function patterns.

    @Override
    protected void run() throws Exception {
        AtomicInteger counter = new AtomicInteger();

        DefinedDataIterator.definedStrings(currentProgram).forEach(data -> {
            String string = (String) data.getValue();

            // Ignore TLV debug messages
            if (string.startsWith("Recvd")) {
                return;
            }

            // Handle special strings to rename caller functions without proper debug strings in locationd
            // "#bbe.Register PDS" -> BasebandEvent::registerPDS
            // "#bb.e, registration action" -> BasebandEvent::registrationAction
            if (string.equals("{\"msg%{public}.0s\":\"#bb.e,Register PDS\"}")) {
                renameReferences(data, "BasebandEvent", "registerPDSIndications");
                return;
            } else if (string.equals("{\"msg%{public}.0s\":\"#bb.e,registration action\"}")) {
                renameReferences(data, "BasebandEvent", "registrationAction");
                return;
            }

            // Try to match the function and class name from the string
            Matcher matcher = CLASS_FUNCTION_PATTERN.matcher(string);
            if (!matcher.find()) {
                return;
            }

            // If successful, apply the label to the function of all references
            applyMatch(data, matcher);

            // Count the number of successful matches
            counter.getAndIncrement();
        });

        println("Matched " + counter.get() + " strings");
    }

    private void applyMatch(Data data, Matcher matcher) {
        // Extract the class and function name from the matched object
        String className = matcher.group(1);
        String functionName = matcher.group(2);

        // Ignore debug messages regarding the standard C++ library
        if (className.equals("std")) {
            return;
        }

        // println("Match: " + className + "::" + functionName);

        // Apply the label to the function of all references
        renameReferences(data, className, functionName);
    }

    private void renameReferences(Data data, String className, String functionName) {
        // Apply the label to the function of all references
        XReferenceUtils.getXReferences(data, -1).forEach(reference -> {
            // Get the function for a given reference
            Function function = getFunctionBefore(reference.getFromAddress());
            try {
                // Assign the function name
                function.setName(functionName, SourceType.ANALYSIS);

                // Check if a class name is set and if apply it to the function
                if (className != null) {
                    // Create a new or get the existing namespace for the class and assign it
                    function.setParentNamespace(NamespaceUtils.createNamespaceHierarchy(
                            className, null, currentProgram, SourceType.ANALYSIS));

                    // Add a comment of both
                    function.setComment(className + "::" + functionName);
                }
            } catch (InvalidInputException | DuplicateNameException | CircularDependencyException e) {
                // Print an error if an exception occurred
                printerr("Can't apply " + className + "::" + functionName +
                        "to " + reference.getFromAddress() + ": " + e.getMessage());
            }
        });
    }
}
