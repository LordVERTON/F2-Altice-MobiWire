// Export function fingerprints from an analyzed ALICE image.
// Usage: -postScript ExportAliceFunctions.java <output.tsv>
//@category ARM

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.FlowType;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Formatter;

public class ExportAliceFunctions extends GhidraScript {

    private String sha256(String s) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] d = md.digest(s.getBytes(StandardCharsets.UTF_8));
        Formatter f = new Formatter();
        for (byte b : d) f.format("%02x", b);
        String out = f.toString();
        f.close();
        return out;
    }

    private String clean(String s) {
        return s.replace("\t", " ").replace("\r", " ").replace("\n", " ");
    }

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 1) {
            throw new IllegalArgumentException(
                "Usage: ExportAliceFunctions.java <output.tsv>");
        }

        File out = new File(args[0]);
        File parent = out.getParentFile();
        if (parent != null) parent.mkdirs();

        Listing listing = currentProgram.getListing();
        FunctionManager fm = currentProgram.getFunctionManager();

        long functionCount = 0;
        long instructionTotal = 0;

        try (PrintWriter pw = new PrintWriter(
                new OutputStreamWriter(
                    new FileOutputStream(out), StandardCharsets.UTF_8))) {

            pw.println("entry\tname\tbody_bytes\tinstructions\tcalls\treturns\tmnemonic_sha256\tmnemonics");

            FunctionIterator fit = fm.getFunctions(true);
            while (fit.hasNext() && !monitor.isCancelled()) {
                Function fn = fit.next();
                AddressSetView body = fn.getBody();
                InstructionIterator ii = listing.getInstructions(body, true);

                StringBuilder mn = new StringBuilder();
                int icount = 0;
                int calls = 0;
                int returns = 0;

                while (ii.hasNext()) {
                    Instruction ins = ii.next();
                    String m = ins.getMnemonicString().toLowerCase();

                    if (icount > 0) mn.append(',');
                    mn.append(m);
                    icount++;

                    FlowType ft = ins.getFlowType();
                    if (ft != null) {
                        if (ft.isCall()) calls++;
                        if (ft.isTerminal()) returns++;
                    }
                }

                if (icount == 0) continue;

                String seq = mn.toString();
                pw.print(fn.getEntryPoint());
                pw.print('\t');
                pw.print(clean(fn.getName()));
                pw.print('\t');
                pw.print(body.getNumAddresses());
                pw.print('\t');
                pw.print(icount);
                pw.print('\t');
                pw.print(calls);
                pw.print('\t');
                pw.print(returns);
                pw.print('\t');
                pw.print(sha256(seq));
                pw.print('\t');
                pw.println(seq);

                functionCount++;
                instructionTotal += icount;
            }
        }

        println("ALICE functions exported: " + functionCount);
        println("ALICE instructions in functions: " + instructionTotal);
        println("Report: " + out.getAbsolutePath());
    }
}
