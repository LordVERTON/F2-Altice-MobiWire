// Export bounded static call trees, no source binary writes.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class DecompileAliceTree extends GhidraScript {
    DecompInterface dec; PrintWriter out;
    Map<String,Integer> visited=new HashMap<>();
    void visit(Address a,int depth) throws Exception {
        String key=a.toString();
        if(visited.containsKey(key) && visited.get(key)<=depth) return;
        visited.put(key,depth);
        Function f=getFunctionAt(a);
        out.println("\n=== depth="+depth+" address="+a+" ===");
        if(f==null) { out.println("No known function at address; not inferred."); return; }
        out.println("name="+f.getName()+" body_bytes="+f.getBody().getNumAddresses());
        out.println("INCOMING");
        ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(a);
        while(ri.hasNext()) {
            Reference r=ri.next(); Function caller=getFunctionContaining(r.getFromAddress());
            out.println(r.getFromAddress()+" "+r.getReferenceType()+" caller="+(caller==null?"unknown":caller.getEntryPoint()));
        }
        List<Address> children=new ArrayList<>();
        out.println("OUTGOING (address order, not execution order)");
        InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);
        int instructions=0,calls=0;
        while(ii.hasNext()) {
            Instruction i=ii.next(); instructions++;
            if(i.getFlowType().isCall()) {
                calls++; out.println(i.getAddress()+" "+i);
                for(Address t:i.getFlows()) children.add(t);
            }
        }
        out.println("instructions="+instructions+" calls="+calls);
        DecompileResults dr=dec.decompileFunction(f,30,monitor);
        if(dr.decompileCompleted()) out.println(dr.getDecompiledFunction().getC());
        else out.println("DECOMPILATION FAILED: "+dr.getErrorMessage());
        if(depth<2) for(Address t:children) visit(t,depth+1);
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        dec=new DecompInterface(); dec.openProgram(currentProgram);
        try(PrintWriter pw=new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8))) {
            out=pw;
            for(int k=1;k<args.length;k++) visit(toAddr(args[k]),0);
            println("Call tree export: "+visited.size()+" addresses -> "+args[0]);
        } finally { dec.dispose(); }
    }
}
