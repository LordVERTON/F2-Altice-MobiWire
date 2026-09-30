// Inspect function pointers installed by FUN_102362a4. Ghidra database only;
// the input firmware image is never modified.
//@category ARM
import ghidra.app.decompiler.*;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class InspectMediaApiTargets extends GhidraScript {
    String addr(Address a) { return a == null ? "?" : a.toString(); }
    @Override public void run() throws Exception {
        String[] args=getScriptArgs();
        int[] ptrCells={0x10236314,0x10236318,0x1023631c,0x10236320,0x10236324,
                        0x10236328,0x1023632c,0x10236330,0x10236334};
        DecompInterface dec=new DecompInterface(); dec.openProgram(currentProgram);
        try(PrintWriter out=new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8))) {
            Set<String> seen=new LinkedHashSet<>();
            for(int cell:ptrCells) {
                Address ca=toAddr(cell); int raw=currentProgram.getMemory().getInt(ca);
                Address target=toAddr(raw & 0xfffffffe);
                out.println("\n===== pointer_cell="+ca+" raw="+String.format("0x%08x",raw)+" thumb="+((raw&1)!=0)+" target="+target+" =====");
                ReferenceIterator cellRefs=currentProgram.getReferenceManager().getReferencesTo(ca);
                while(cellRefs.hasNext()) { Reference r=cellRefs.next(); out.println("CELL_XREF "+r.getFromAddress()+" "+r.getReferenceType()+" "+r.getOperandIndex()); }
                ReferenceIterator refs=currentProgram.getReferenceManager().getReferencesTo(target);
                while(refs.hasNext()) { Reference r=refs.next(); Function caller=getFunctionContaining(r.getFromAddress()); out.println("TARGET_XREF "+r.getFromAddress()+" "+r.getReferenceType()+" caller="+(caller==null?"?":caller.getEntryPoint())); }
                Function f=getFunctionAt(target);
                if(f==null) {
                    ArmDisassembleCommand cmd=new ArmDisassembleCommand(target,null,true);
                    boolean ok=cmd.applyTo(currentProgram,monitor);
                    out.println("THUMB_DISASSEMBLE="+ok);
                    f=getFunctionAt(target);
                    if(f==null && ok) f=createFunction(target,"FUN_"+target.toString());
                }
                if(f==null) { out.println("NO_FUNCTION_CREATED"); continue; }
                seen.add(f.getEntryPoint().toString());
                out.println("FUNCTION name="+f.getName()+" entry="+f.getEntryPoint()+" bytes="+f.getBody().getNumAddresses()+" min="+f.getBody().getMinAddress()+" max="+f.getBody().getMaxAddress()+" thunk="+f.isThunk());
                InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(ii.hasNext()) { Instruction i=ii.next(); out.println("INS "+i.getAddress()+" "+i); }
                DecompileResults dr=dec.decompileFunction(f,45,monitor);
                out.println("DECOMPILE\n"+(dr.decompileCompleted()?dr.getDecompiledFunction().getC():"FAILED "+dr.getErrorMessage()));
            }
            out.println("\nFunctions inspected: "+seen.size());
            println("Media API targets exported to "+args[0]);
        } finally { dec.dispose(); }
    }
}
