import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.Reference;

import java.io.File;
import java.io.PrintWriter;

public class DumpFunctionAsm extends GhidraScript {

    private String hex(byte[] data) {
        StringBuilder sb = new StringBuilder();

        for (byte b : data) {
            if (sb.length() > 0) sb.append(" ");
            sb.append(String.format("%02X", b & 0xff));
        }

        return sb.toString();
    }

    @Override
    public void run() throws Exception {

        String[] args = getScriptArgs();

        if (args.length < 2) {
            println("Usage: DumpFunctionAsm.java <address> <output-file>");
            return;
        }

        Address addr = toAddr(args[0]);

        Function f = getFunctionContaining(addr);

        if (f == null) {
            f = getFunctionAt(addr);
        }

        if (f == null) {
            println("No function for " + addr);
            return;
        }

        File output = new File(args[1]);
        PrintWriter out = new PrintWriter(output, "UTF-8");

        out.println("FUNCTION");
        out.println("name  = " + f.getName());
        out.println("entry = " + f.getEntryPoint());
        out.println("body  = " + f.getBody());
        out.println();

        Listing listing = currentProgram.getListing();
        InstructionIterator it =
            listing.getInstructions(f.getBody(), true);

        while (it.hasNext() && !monitor.isCancelled()) {

            Instruction ins = it.next();

            String bytes;

            try {
                bytes = hex(ins.getBytes());
            }
            catch (Exception e) {
                bytes = "??";
            }

            out.printf(
                "%s  %-17s  %-8s %s%n",
                ins.getAddress(),
                bytes,
                ins.getMnemonicString(),
                ins.toString().substring(
                    ins.getMnemonicString().length()
                ).trim()
            );

            for (Reference ref : ins.getReferencesFrom()) {

                out.printf(
                    "    REF -> %-12s type=%s%n",
                    ref.getToAddress(),
                    ref.getReferenceType()
                );
            }
        }

        out.close();

        println("Written: " + output.getAbsolutePath());
    }
}
