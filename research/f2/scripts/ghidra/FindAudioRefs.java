// Recherche automatique des indices audio et de leurs références dans un programme Ghidra.
// Utilisation prévue avec analyzeHeadless en -postScript.
// Lecture seule : ce script ne modifie pas le binaire.

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import java.nio.charset.StandardCharsets;

public class FindAudioRefs extends GhidraScript {

    private byte[] le32(long v) {
        return new byte[] {
            (byte)(v & 0xff),
            (byte)((v >>> 8) & 0xff),
            (byte)((v >>> 16) & 0xff),
            (byte)((v >>> 24) & 0xff)
        };
    }

    private String functionNameAt(FunctionManager fm, Address a) {
        Function f = fm.getFunctionContaining(a);
        if (f != null) {
            return f.getName() + " @ " + f.getEntryPoint();
        }
        return "(hors fonction reconnue)";
    }

    @Override
    public void run() throws Exception {
        String[] targets = new String[] {
            "FMradio",
            "audio/mp3",
            "audio/mpeg3",
            "audio/x-mp3",
            "audio/aac",
            "audio/x-mpeg-aac",
            "AT+EMAUDIO",
            "DAF",
            "AUDPLY",
            "AudioPlayer",
            "Audio player",
            "Playlist",
            "Play list",
            "Music",
            "Image viewer"
        };

        Memory memory = currentProgram.getMemory();
        ReferenceManager refs = currentProgram.getReferenceManager();
        FunctionManager funcs = currentProgram.getFunctionManager();

        Address min = memory.getMinAddress();
        Address max = memory.getMaxAddress();

        println("============================================================");
        println("Programme : " + currentProgram.getName());
        println("Image base: " + currentProgram.getImageBase());
        println("Memory    : " + min + " -> " + max);
        println("============================================================");

        for (String target : targets) {
            byte[] needle = target.getBytes(StandardCharsets.US_ASCII);
            Address cursor = min;
            boolean foundAny = false;

            while (cursor != null && cursor.compareTo(max) <= 0 && !monitor.isCancelled()) {
                Address hit = memory.findBytes(cursor, max, needle, null, true, monitor);
                if (hit == null) {
                    break;
                }

                foundAny = true;
                println("");
                println("=== \"" + target + "\" @ " + hit + " ===");

                // Références reconnues par Ghidra
                int xrefCount = 0;
                ReferenceIterator it = refs.getReferencesTo(hit);
                while (it.hasNext()) {
                    Reference r = it.next();
                    Address from = r.getFromAddress();
                    println("  XREF Ghidra : " + from +
                            "  type=" + r.getReferenceType() +
                            "  " + functionNameAt(funcs, from));
                    xrefCount++;
                }
                if (xrefCount == 0) {
                    println("  XREF Ghidra : aucun");
                }

                // Recherche brute de l'adresse 32 bits en little-endian.
                long off = hit.getOffset() & 0xffffffffL;
                byte[] ptr = le32(off);
                Address pcursor = min;
                int rawCount = 0;
                while (pcursor != null && pcursor.compareTo(max) <= 0 && !monitor.isCancelled()) {
                    Address phit = memory.findBytes(pcursor, max, ptr, null, true, monitor);
                    if (phit == null) {
                        break;
                    }
                    if (!phit.equals(hit)) {
                        println("  PTR brut    : " + phit +
                                " -> " + hit +
                                "  " + functionNameAt(funcs, phit));
                        rawCount++;
                    }
                    try {
                        pcursor = phit.add(1);
                    } catch (AddressOutOfBoundsException e) {
                        break;
                    }
                }
                if (rawCount == 0) {
                    println("  PTR brut    : aucun pointeur absolu 32-bit trouvé");
                }

                try {
                    cursor = hit.add(1);
                } catch (AddressOutOfBoundsException e) {
                    break;
                }
            }

            if (!foundAny) {
                println("");
                println("=== \"" + target + "\" : ABSENT ===");
            }
        }

        println("");
        println("============================================================");
        println("Fin de l'analyse audio.");
        println("============================================================");
    }
}
