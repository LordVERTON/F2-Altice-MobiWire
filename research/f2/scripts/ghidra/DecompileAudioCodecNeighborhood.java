// Compact, read-only decompilation of functions around WAV/AMR source markers.
//@category ARM
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DecompileAudioCodecNeighborhood extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        int[] entries={0x101f509c,0x101f50ac,0x101f5434,0x101f5594,0x101f5664,
          0x101f576c,0x101f59f0,0x101f61d0,0x101f6474,0x101f67e8,0x101f67f8,
          0x101f6a54,0x101f6f7a,0x102a081e,0x102a08c4,0x102a091c,0x102a0998,
          0x102a0a04,0x102a0b40,0x102a0b94,0x102a0da4,0x102a0dcc,0x102a0f20};
        DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
        try(PrintWriter out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8))) {
          for(int ea:entries) {
            Function f=getFunctionAt(toAddr(ea));
            out.println("\n===== "+String.format("0x%08x",ea)+" =====");
            if(f==null) { out.println("NO_FUNCTION"); continue; }
            out.println("name="+f.getName()+" entry="+f.getEntryPoint()+" bytes="+f.getBody().getNumAddresses());
            ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
            while(ri.hasNext()) { Reference r=ri.next(); Function caller=getFunctionContaining(r.getFromAddress()); out.println("XREF "+r.getFromAddress()+" caller="+(caller==null?"?":caller.getEntryPoint())); }
            DecompileResults dr=dec.decompileFunction(f,30,monitor);
            if(dr.decompileCompleted()) out.println(dr.getDecompiledFunction().getC()); else out.println("DECOMPILE_FAILED "+dr.getErrorMessage());
          }
          println("Audio codec neighborhood report: "+args[0]);
        } finally { dec.dispose(); }
    }
}
