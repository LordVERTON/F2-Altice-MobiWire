// Read-only trace of QMobile MIME/audio string pointer cells and their callers.
//@category ARM
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class TraceQMobileAudioRefs extends GhidraScript {
    private final Set<String> emitted = new LinkedHashSet<>();
    private DecompInterface dec;
    private PrintWriter out;
    private void log(String s) { out.println(s); println(s); }
    private String functionAt(Address a) {
        Function f = getFunctionContaining(a);
        return f == null ? null : f.getEntryPoint().toString();
    }
    private void dumpFunction(Address a) {
        Function f = getFunctionContaining(a);
        if (f == null || !emitted.add(f.getEntryPoint().toString())) return;
        log("\n===== FUNCTION " + f.getEntryPoint() + " " + f.getName() + " bytes=" + f.getBody().getNumAddresses() + " =====");
        DecompileResults dr = dec.decompileFunction(f, 45, monitor);
        log(dr.decompileCompleted() ? dr.getDecompiledFunction().getC() : "DECOMPILE FAILED: " + dr.getErrorMessage());
    }
    private void traceAddress(long value, String label) throws Exception {
        Address target = toAddr(value);
        log("\n=== " + label + " target=" + target + " ===");
        ReferenceIterator refs = currentProgram.getReferenceManager().getReferencesTo(target);
        int n = 0;
        while (refs.hasNext()) {
            Reference r = refs.next(); n++;
            log("XREF " + r.getFromAddress() + " " + r.getReferenceType() + " caller=" + functionAt(r.getFromAddress()));
            dumpFunction(r.getFromAddress());
        }
        if (n == 0) log("No Ghidra references.");
        byte[] needle = new byte[] {(byte)value,(byte)(value>>>8),(byte)(value>>>16),(byte)(value>>>24)};
        Memory mem = currentProgram.getMemory();
        Address cursor = mem.getMinAddress(); int raw = 0;
        while (cursor != null && cursor.compareTo(mem.getMaxAddress()) <= 0) {
            Address cell = mem.findBytes(cursor, mem.getMaxAddress(), needle, null, true, monitor);
            if (cell == null) break;
            if (!cell.equals(target)) {
                raw++;
                log("PTR32 " + cell + " -> " + target + " containing=" + functionAt(cell));
                ReferenceIterator cellRefs = currentProgram.getReferenceManager().getReferencesTo(cell);
                while (cellRefs.hasNext()) {
                    Reference cr = cellRefs.next();
                    log("  CELL_XREF " + cr.getFromAddress() + " " + cr.getReferenceType() + " caller=" + functionAt(cr.getFromAddress()));
                    dumpFunction(cr.getFromAddress());
                }
                long word = mem.getInt(cell) & 0xffffffffL;
                log(String.format("  value_at_cell=0x%08x", word));
            }
            cursor = cell.add(1);
        }
        if (raw == 0) log("No raw absolute pointer cell.");
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        dec = new DecompInterface(); dec.openProgram(currentProgram);
        try (PrintWriter pw = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8))) {
            out = pw;
            log("QMobile F2 ROM audio/MIME reference trace; read-only; program=" + currentProgram.getName());
            long[] targets = {0x100dfaa2L,0x100dfa7fL,0x100dfa96L,0x100d5a73L,0x100d5aa2L,0x100d5ae9L,0x100d5d27L,0x100e1215L,0x100d5b92L};
            String[] labels = {"audio/mp3","audio/mpeg3","audio/x-mp3","video/3gpp2","audio/mp3 MIME family","audio/aac","audio/amr","FMradio","audio/x-mpeg"};
            for (int i=0;i<targets.length;i++) traceAddress(targets[i],labels[i]);
            log("\nFunctions decompiled=" + emitted.size());
        } finally { dec.dispose(); }
    }
}
