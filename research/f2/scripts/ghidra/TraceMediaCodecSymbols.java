// Read-only XREF inventory for concrete audio decoder/media symbols in Altice ALICE.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class TraceMediaCodecSymbols extends GhidraScript {
    private PrintWriter out;
    private void emit(String s) { println(s); if (out != null) out.println(s); }
    private byte[] le32(long v) { return new byte[] {(byte)v,(byte)(v>>>8),(byte)(v>>>16),(byte)(v>>>24)}; }
    private String fn(Address a) {
        Function f = getFunctionContaining(a);
        return f == null ? "(hors fonction reconnue)" : f.getName() + " @ " + f.getEntryPoint();
    }
    private void search(String term, String encoding, byte[] needle, Memory mem, Address min, Address max) throws Exception {
        Address cursor = min;
        int hits = 0;
        while (cursor != null && cursor.compareTo(max) <= 0 && !monitor.isCancelled()) {
            Address hit = mem.findBytes(cursor, max, needle, null, true, monitor);
            if (hit == null) break;
            hits++;
            emit("\n=== " + term + " [" + encoding + "] @ " + hit + " ===");
            int refs = 0;
            ReferenceIterator it = currentProgram.getReferenceManager().getReferencesTo(hit);
            while (it.hasNext()) {
                Reference r = it.next();
                emit("XREF " + r.getFromAddress() + " " + r.getReferenceType() + " " + fn(r.getFromAddress()));
                refs++;
            }
            if (refs == 0) emit("XREF Ghidra: aucun");
            byte[] ptr = le32(hit.getOffset());
            Address p = min;
            int ptrs = 0;
            while (p != null && p.compareTo(max) <= 0 && !monitor.isCancelled()) {
                Address ph = mem.findBytes(p, max, ptr, null, true, monitor);
                if (ph == null) break;
                if (!ph.equals(hit)) {
                    emit("PTR32 " + ph + " -> " + hit + " " + fn(ph));
                    ptrs++;
                }
                p = ph.add(1);
            }
            if (ptrs == 0) emit("PTR32 absolu: aucun");
            cursor = hit.add(1);
        }
        if (hits == 0) emit("\n=== " + term + " [" + encoding + "]: ABSENT ===");
    }
    @Override public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length > 0) out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]), StandardCharsets.UTF_8));
        Memory mem = currentProgram.getMemory();
        Address min = mem.getMinAddress(), max = mem.getMaxAddress();
        emit("Programme=" + currentProgram.getName() + " mémoire=" + min + ".." + max + " (lecture seule)");
        String[] terms = {"hal\\audio\\src\\common\\src\\WavDecoder.c", "hal\\audio\\src\\common\\src\\AmrParser.c", "media\\audio\\src\\aud_player_media.c", "WavDecoder.c", "AmrParser.c", "aud_player_media.c", "audio_play_list", "MP3", "MPEG", "AAC", "DAF", "PCM", "IMA_ADPCM"};
        for (String t : terms) {
            search(t, "ASCII", t.getBytes(StandardCharsets.US_ASCII), mem, min, max);
            search(t, "UTF-16LE", t.getBytes(StandardCharsets.UTF_16LE), mem, min, max);
        }
        if (out != null) { out.flush(); out.close(); }
    }
}
