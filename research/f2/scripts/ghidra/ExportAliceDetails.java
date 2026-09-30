// Read-only export of instructions, operands, flows, references and selected decompilations.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;
import com.google.gson.Gson;
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.*;

public class ExportAliceDetails extends GhidraScript {
    String addr(Address a) { return a == null ? null : a.toString(); }
    Map<String,Object> ref(Reference r) {
        Map<String,Object> m = new LinkedHashMap<>();
        m.put("from",addr(r.getFromAddress())); m.put("to",addr(r.getToAddress()));
        m.put("type",r.getReferenceType().toString());
        Function f = getFunctionContaining(r.getFromAddress());
        m.put("caller",f == null ? null : addr(f.getEntryPoint()));
        return m;
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        Gson gson = new Gson();
        Set<String> selected = new HashSet<>();
        for (int i=1;i<args.length;i++) selected.add(args[i].toLowerCase().replace("0x",""));
        DecompInterface dec = new DecompInterface();
        dec.openProgram(currentProgram);
        try (PrintWriter out = new PrintWriter(new OutputStreamWriter(new FileOutputStream(args[0]),StandardCharsets.UTF_8))) {
            FunctionIterator fs = currentProgram.getFunctionManager().getFunctions(true);
            int count=0;
            while(fs.hasNext() && !monitor.isCancelled()) {
                Function f=fs.next();
                Map<String,Object> row=new LinkedHashMap<>();
                String entry=addr(f.getEntryPoint());
                row.put("entry",entry); row.put("name",f.getName());
                row.put("bytes",f.getBody().getNumAddresses());
                row.put("min",addr(f.getBody().getMinAddress())); row.put("max",addr(f.getBody().getMaxAddress()));
                row.put("thunk",f.isThunk() ? addr(f.getThunkedFunction(true).getEntryPoint()) : null);
                List<Object> incoming=new ArrayList<>();
                ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(f.getEntryPoint());
                while(ri.hasNext()) incoming.add(ref(ri.next()));
                row.put("incoming",incoming);
                List<Object> instructions=new ArrayList<>();
                InstructionIterator ii=currentProgram.getListing().getInstructions(f.getBody(),true);
                while(ii.hasNext()) {
                    Instruction ins=ii.next(); Map<String,Object> x=new LinkedHashMap<>();
                    x.put("address",addr(ins.getAddress())); x.put("text",ins.toString());
                    x.put("mnemonic",ins.getMnemonicString().toLowerCase()); x.put("length",ins.getLength());
                    StringBuilder hex=new StringBuilder(); for(byte b:ins.getBytes()) hex.append(String.format("%02x",b&255));
                    x.put("hex",hex.toString());
                    List<String> operands=new ArrayList<>();
                    for(int k=0;k<ins.getNumOperands();k++) operands.add(ins.getDefaultOperandRepresentation(k));
                    x.put("operands",operands);
                    x.put("flow",ins.getFlowType().toString()); x.put("call",ins.getFlowType().isCall());
                    x.put("jump",ins.getFlowType().isJump()); x.put("conditional",ins.getFlowType().isConditional());
                    x.put("terminal",ins.getFlowType().isTerminal()); x.put("fallthrough",addr(ins.getFallThrough()));
                    List<String> flows=new ArrayList<>(); for(Address a:ins.getFlows()) flows.add(addr(a));
                    x.put("targets",flows);
                    List<Object> refs=new ArrayList<>();
                    for(Reference r:ins.getReferencesFrom()) {
                        Map<String,Object> rr=ref(r);
                        if(r.getReferenceType().isData() && currentProgram.getMemory().contains(r.getToAddress())) {
                            try { rr.put("u32",String.format("%08x",currentProgram.getMemory().getInt(r.getToAddress()))); } catch(Exception e) {}
                            Data data=getDataContaining(r.getToAddress());
                            if(data!=null && data.hasStringValue()) rr.put("string",data.getDefaultValueRepresentation());
                        }
                        refs.add(rr);
                    }
                    x.put("refs",refs); instructions.add(x);
                }
                row.put("instructions",instructions);
                if(selected.contains(entry)) {
                    DecompileResults dr=dec.decompileFunction(f,45,monitor);
                    row.put("decompile_error",dr.getErrorMessage());
                    if(dr.decompileCompleted()) row.put("decompiled",dr.getDecompiledFunction().getC());
                }
                out.println(gson.toJson(row)); count++;
            }
            println("Exported detailed functions: "+count+" -> "+args[0]);
        } finally { dec.dispose(); }
    }
}
