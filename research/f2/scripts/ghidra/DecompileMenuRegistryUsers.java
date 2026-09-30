// Read-only decompilation of secondary users of platform child-list APIs.
//@category ARM
import ghidra.app.decompiler.*;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;

public class DecompileMenuRegistryUsers extends GhidraScript {
  public void run() throws Exception {
    String[] args=getScriptArgs(); int[] entries={0x102d43dc,0x102d441c};
    DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
    try(PrintWriter out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8))) {
      for(int ea:entries) {
        Function f=getFunctionAt(toAddr(ea)); out.println("\n===== "+String.format("0x%08x",ea)+" =====");
        if(f==null){out.println("NO_FUNCTION");continue;}
        out.println("name="+f.getName()+" bytes="+f.getBody().getNumAddresses());
        ReferenceIterator incoming=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
        while(incoming.hasNext()){Reference r=incoming.next();Function caller=getFunctionContaining(r.getFromAddress());out.println("XREF "+r.getFromAddress()+" caller="+(caller==null?"?":caller.getEntryPoint()));}
        InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);
        while(ii.hasNext()){Instruction i=ii.next();if(i.getFlowType().isCall())out.println("CALL "+i.getAddress()+" "+i);}
        DecompileResults dr=dec.decompileFunction(f,30,monitor);
        out.println(dr.decompileCompleted()?dr.getDecompiledFunction().getC():"DECOMPILE_FAILED "+dr.getErrorMessage());
      }
    } finally { dec.dispose(); }
  }
}
