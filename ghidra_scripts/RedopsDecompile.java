// RedopsDecompile — headless decompile of a single function.
//
// Invoked by rebin_mcp.py via analyzeHeadless:
//   analyzeHeadless <proj> <name> -process <bin> -noanalysis \
//       -scriptPath <dir> -postScript RedopsDecompile.java <target> <outfile>
//
// <target>  is a function address (0x140014e60) or a function name.
// <outfile> is where the decompiled C is written (Ghidra's logger prefixes
//           every println, so we write to a file the caller reads instead).

import java.io.FileWriter;
import java.io.Writer;

import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.program.model.address.Address;

public class RedopsDecompile extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) {
            println("REDOPS_ERR: usage: <target> <outfile>");
            return;
        }
        String target = args[0];
        String outfile = args[1];

        String body;
        Function func = resolve(target);
        if (func == null) {
            body = "REDOPS_ERR: function not found: " + target;
        } else {
            DecompInterface di = new DecompInterface();
            di.openProgram(currentProgram);
            try {
                DecompileResults res = di.decompileFunction(func, 90, monitor);
                if (res != null && res.decompileCompleted()) {
                    body = "// " + func.getName() + " @ " + func.getEntryPoint()
                            + "\n" + res.getDecompiledFunction().getC();
                } else {
                    String err = (res != null) ? res.getErrorMessage() : "null result";
                    body = "REDOPS_ERR: decompile failed: " + err;
                }
            } finally {
                di.dispose();
            }
        }

        try (Writer w = new FileWriter(outfile)) {
            w.write(body);
        }
        println("REDOPS_DONE: " + outfile);
    }

    private Function resolve(String target) {
        FunctionManager fm = currentProgram.getFunctionManager();
        // Try as an address first
        try {
            Address addr = currentProgram.getAddressFactory().getAddress(target);
            if (addr != null) {
                Function f = fm.getFunctionContaining(addr);
                if (f == null) {
                    f = getFunctionAt(addr);
                }
                if (f != null) {
                    return f;
                }
            }
        } catch (Exception e) {
            // not an address; fall through to name lookup
        }
        // Try by exact name
        for (Function f : fm.getFunctions(true)) {
            if (f.getName().equals(target)) {
                return f;
            }
        }
        return null;
    }
}
