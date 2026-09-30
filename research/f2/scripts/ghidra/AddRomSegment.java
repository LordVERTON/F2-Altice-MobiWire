// Add the GFH-addressed service ROM image as a separate memory block in an ALICE program.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;
import java.io.ByteArrayInputStream;
import java.nio.file.Files;
import java.nio.file.Paths;

public class AddRomSegment extends GhidraScript {
    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 2) throw new IllegalArgumentException("Usage: AddRomSegment.java <ROM-file> <GFH-load-address>");
        byte[] bytes = Files.readAllBytes(Paths.get(args[0]));
        Address start = toAddr(Long.decode(args[1]));
        MemoryBlock block = currentProgram.getMemory().createInitializedBlock(
            "ROM_service_package", start, new ByteArrayInputStream(bytes), bytes.length, monitor, false);
        block.setRead(true);
        block.setWrite(false);
        block.setExecute(true);
        println("Added ROM_service_package: " + start + " .. " + block.getEnd() + " (" + bytes.length + " bytes)");
    }
}
