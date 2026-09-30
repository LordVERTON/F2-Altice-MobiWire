// Dedicated ALICE runtime-address database, with DAF overlay only.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.mem.MemoryBlock;
import java.io.ByteArrayInputStream;
import java.nio.file.*;

public class PrepareMp3Image extends GhidraScript {
    void add(String name, String path, long base) throws Exception {
        byte[] data=Files.readAllBytes(Paths.get(path));
        MemoryBlock block=currentProgram.getMemory().createInitializedBlock(
            name,toAddr(base),new ByteArrayInputStream(data),data.length,monitor,false);
        block.setRead(true); block.setWrite(false); block.setExecute(true);
    }
    public void run() throws Exception {
        String[] args=getScriptArgs();
        if(args.length!=2) throw new IllegalArgumentException("platform directory and ROM path required");
        add("zimage",args[0]+"/zimage.bin",0xF023CA50L);
        add("boot_zimage",args[0]+"/boot_zimage.bin",0xF01F19E4L);
        add("DAF_overlay",args[0]+"/dcm_010c.bin",0xF03D84E0L);
        add("ROM",args[1],0x1000A000L);
        // ALICE is imported at 0x1024EC00; ROM offset 0x5BA8 gives base/size.
        if(getInt(toAddr(0x1000FBA8L))!=0x1024EC00 || getInt(toAddr(0x1000FBACL))!=1407924)
            throw new IllegalStateException("ALICE runtime range differs from validated ROM");
    }
}
