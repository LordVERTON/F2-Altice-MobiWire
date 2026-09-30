// Import recovered platform blocks into a new analysis database, without changing binaries.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class PreparePlatformImage extends GhidraScript {
    void add(String name, String path, long base) throws Exception {
        byte[] data = Files.readAllBytes(Paths.get(path));
        MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
            name, toAddr(base), new ByteArrayInputStream(data), data.length, monitor, false);
        block.setRead(true); block.setWrite(false); block.setExecute(true);
    }
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if(args.length != 3) throw new IllegalArgumentException("boot_zimage ALICE ROM paths required");
        add("boot_zimage", args[0], 0xF01F19E4L);
        add("ALICE", args[1], 0x101812C4L);
        add("ROM", args[2], 0x1000A000L);
        // Do not combine DCM overlays: DAF and wavetable share execution addresses.
        for(long value : new long[]{0xF02D8870L, 0xF032ACDCL, 0xF02E01B0L}) {
            Address a = toAddr(value);
            new ArmDisassembleCommand(a, null, true).applyTo(currentProgram, monitor);
            if(getFunctionAt(a) == null) createFunction(a, null);
        }
    }
}
