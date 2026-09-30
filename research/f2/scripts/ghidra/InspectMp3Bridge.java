// Bounded inspection of existing ALICE analysis; no firmware writes.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import ghidra.program.model.address.*;
import java.io.*;
import java.util.*;

public class InspectMp3Bridge extends GhidraScript {
    public void run() throws Exception {
        String[] args=getScriptArgs();
        DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
        Set<Function> functions=new LinkedHashSet<>();
        try(PrintWriter out=new PrintWriter(args[0], "UTF-8")) {
            for(int i=1;i<args.length;i++) {
                boolean force=args[i].startsWith("thumb:");
                Address a=toAddr(force?args[i].substring(6):args[i]);
                if(force) {
                    new ArmDisassembleCommand(a,null,true).applyTo(currentProgram,monitor);
                    if(getFunctionAt(a)==null) createFunction(a,null);
                }
                Function f=getFunctionContaining(a);
                out.println("TARGET "+a+" function="+(f==null?"unknown":f.getEntryPoint()));
                if(f!=null) functions.add(f);
                ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(a);
                while(refs.hasNext()) {
                    Reference r=refs.next();
                    Function caller=getFunctionContaining(r.getFromAddress());
                    out.println("  "+r+" caller="+(caller==null?"unknown":caller.getEntryPoint()));
                    if(caller!=null) functions.add(caller);
                }
            }
            for(Function f:new ArrayList<Function>(functions)) {
                ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
                while(refs.hasNext()) {
                    Reference r=refs.next();
                    Function caller=getFunctionContaining(r.getFromAddress());
                    out.println("CALLER "+f.getEntryPoint()+" <- "+r+" function="+(caller==null?"unknown":caller.getEntryPoint()));
                    if(caller!=null) functions.add(caller);
                }
            }
            for(Function f:functions) {
                out.println("\nFUNCTION "+f.getEntryPoint()+" "+f.getName());
                DecompileResults result=dec.decompileFunction(f,30,monitor);
                out.println(result.decompileCompleted()?result.getDecompiledFunction().getC():result.getErrorMessage());
            }
        } finally { dec.dispose(); }
    }
}
