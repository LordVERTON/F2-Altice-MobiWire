// ALICE BL/BLX normalization in the imported analysis program ONLY.
// Never writes a binary or modifies the source file. Algorithm: local unalice.py.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.address.Address;

public class AnalyzeAliceNormalized extends GhidraScript {
    public void run() throws Exception {
        Address base=currentProgram.getMemory().getMinAddress();
        int size=(int)currentProgram.getMemory().getSize();
        byte[] b=new byte[size]; currentProgram.getMemory().getBytes(base,b);
        int n=0;
        for(int off=0;off+3<size;off+=2) {
            int ptr=off/2;
            if((ptr+1)%32==0) continue;
            int hi=(b[off]&255)|((b[off+1]&255)<<8);
            int lo=(b[off+2]&255)|((b[off+3]&255)<<8);
            if((hi&0xf800)!=0xf000) continue;
            int type=lo&0xf800;
            if(type!=0xf800 && type!=0xe800) continue;
            long encoded=((hi&0x7ff)<<12)+((lo&0x7ff)<<1);
            long v=(encoded/2)-(ptr-1)+((hi&0x400)!=0 ? 0x7ffffffeL : -2L);
            hi=(int)((v>>11)&0x7ff)|0xf000; lo=(int)(v&0x7ff)|type;
            b[off]=(byte)hi; b[off+1]=(byte)(hi>>8);
            b[off+2]=(byte)lo; b[off+3]=(byte)(lo>>8); n++; off+=2;
        }
        currentProgram.getMemory().setBytes(base,b);
        println("Normalized BL/BLX pairs in analysis database only: "+n);
        new ArmDisassembleCommand(base,null,true).applyTo(currentProgram,monitor);
        for(String arg:getScriptArgs()) {
            Address a=toAddr(arg);
            new ArmDisassembleCommand(a,null,true).applyTo(currentProgram,monitor);
            createFunction(a,null);
        }
    }
}
