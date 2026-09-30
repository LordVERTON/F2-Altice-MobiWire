//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

public class InspectAliceCallsite extends GhidraScript {
    public void run() throws Exception {
        String outPath = getScriptArgs()[0];
        try (java.io.PrintWriter out = new java.io.PrintWriter(outPath, "UTF-8")) {
            for (int n = 1; n < getScriptArgs().length; n++) {
                Address a = toAddr(getScriptArgs()[n]);
                out.println("=== " + a + " ===");
                int span = a.toString().toLowerCase().endsWith("103bd438") ? -256 : -16;
                for (int d = span; d <= 16; d += 2) {
                    Address p = a.add(d);
                    Instruction ins = getInstructionAt(p);
                    if (ins != null) out.println(p + " " + ins);
                    else {
                        Data data = getDataAt(p);
                        if (data != null) out.println(p + " DATA " + data);
                    }
                }
                ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(a);
                while (refs.hasNext()) {
                    Reference r = refs.next();
                    Function f = getFunctionContaining(r.getFromAddress());
                    out.println("REF " + r.getFromAddress() + " type=" + r.getReferenceType() +
                        " fromFunction=" + (f == null ? "unknown" : f.getEntryPoint()));
                }
            }
        }
    }
}
