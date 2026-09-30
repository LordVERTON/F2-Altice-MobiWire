// Locate the candidate Playlist resource and report Ghidra/raw-pointer references.
// Read-only postScript for the existing Altice ALICE project.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import ghidra.app.decompiler.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class FindPlaylistResourceRefs extends GhidraScript {
    private PrintWriter report;
    private void emit(String s) { println(s); if (report != null) report.println(s); }
    private byte[] le32(long v) {
        return new byte[] {(byte)v,(byte)(v >>> 8),(byte)(v >>> 16),(byte)(v >>> 24)};
    }
    private byte[] utf16le(String s) {
        return s.getBytes(StandardCharsets.UTF_16LE);
    }
    private String fn(Address a) {
        Function f = getFunctionContaining(a);
        return f == null ? "(hors fonction reconnue)" : f.getName() + " @ " + f.getEntryPoint();
    }
    private void search(byte[] needle, String label, Memory memory, Address min, Address max,
                        ReferenceManager refs) throws Exception {
        Address cursor = min;
        int found = 0;
        while (cursor != null && cursor.compareTo(max) <= 0 && !monitor.isCancelled()) {
            Address hit = memory.findBytes(cursor, max, needle, null, true, monitor);
            if (hit == null) break;
            found++;
            emit("\n=== " + label + " @ " + hit + " ===");
            int xr = 0;
            ReferenceIterator it = refs.getReferencesTo(hit);
            while (it.hasNext()) {
                Reference r = it.next();
                emit("  XREF " + r.getFromAddress() + " " + r.getReferenceType() + " " + fn(r.getFromAddress()));
                xr++;
            }
            if (xr == 0) emit("  XREF Ghidra: aucun");

            byte[] ptr = le32(hit.getOffset());
            Address pc = min;
            int pcnt = 0;
            while (pc != null && pc.compareTo(max) <= 0 && !monitor.isCancelled()) {
                Address ph = memory.findBytes(pc, max, ptr, null, true, monitor);
                if (ph == null) break;
                if (!ph.equals(hit)) {
                    emit("  PTR 32-bit " + ph + " -> " + hit + " " + fn(ph));
                    pcnt++;
                }
                pc = ph.add(1);
            }
            if (pcnt == 0) emit("  PTR absolu 32-bit: aucun");
            cursor = hit.add(1);
        }
        if (found == 0) emit("\n=== " + label + ": ABSENT ===");
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 0) report = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8));
        Memory memory = currentProgram.getMemory();
        Address min = memory.getMinAddress(), max = memory.getMaxAddress();
        emit("Programme=" + currentProgram.getName() + " imageBase=" + currentProgram.getImageBase());
        emit("Memory=" + min + ".." + max);
        search("Playlist".getBytes(StandardCharsets.US_ASCII), "Playlist ASCII", memory, min, max, currentProgram.getReferenceManager());
        search(utf16le("Playlist"), "Playlist UTF-16LE", memory, min, max, currentProgram.getReferenceManager());
        search("audio_play_list".getBytes(StandardCharsets.US_ASCII), "audio_play_list ASCII", memory, min, max, currentProgram.getReferenceManager());
        search(utf16le("audio_play_list"), "audio_play_list UTF-16LE", memory, min, max, currentProgram.getReferenceManager());
        search(utf16le(".MP4"), ".MP4 UTF-16LE adjacent type list", memory, min, max, currentProgram.getReferenceManager());
        Address candidate = toAddr(0x10287048L);
        Function f = getFunctionAt(candidate);
        if (f != null) {
            emit("\n=== Fonction associée à l'XREF .MP4: " + f.getName() + " @ " + f.getEntryPoint() + " ===");
            ReferenceIterator incoming = currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            int callerCount = 0;
            Function firstCaller = null;
            while (incoming.hasNext()) {
                Reference r = incoming.next();
                Function caller = getFunctionContaining(r.getFromAddress());
                emit("CALLER " + r.getFromAddress() + " " + (caller == null ? "(non attribué)" : caller.getName() + " @ " + caller.getEntryPoint()));
                if (firstCaller == null) firstCaller = caller;
                callerCount++;
            }
            if (callerCount == 0) emit("Aucun caller direct reconnu par Ghidra.");
            DecompInterface dec = new DecompInterface();
            dec.openProgram(currentProgram);
            DecompileResults dr = dec.decompileFunction(f, 45, monitor);
            if (dr.decompileCompleted()) emit(dr.getDecompiledFunction().getC());
            else emit("Décompilation indisponible: " + dr.getErrorMessage());
            if (firstCaller != null) {
                emit("\n=== Caller direct " + firstCaller.getName() + " @ " + firstCaller.getEntryPoint() + " ===");
                DecompileResults callerDr = dec.decompileFunction(firstCaller, 45, monitor);
                if (callerDr.decompileCompleted()) emit(callerDr.getDecompiledFunction().getC());
                else emit("Décompilation caller indisponible: " + callerDr.getErrorMessage());
            }
            dec.dispose();
        }
        if (report != null) { report.flush(); report.close(); }
    }
}
