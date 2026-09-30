// Report whether external menu API addresses are backed by the combined ROM+ALICE image.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;

public class CheckCombinedMenuApis extends GhidraScript {
    @Override
    public void run() throws Exception {
        for (long a : new long[]{0x1000A000L, 0x101812C4L, 0x1027572CL, 0x10275732L, 0x10275798L, 0xF02D8870L, 0xF032ACDCL}) {
            Address at = toAddr(a);
            MemoryBlock b = currentProgram.getMemory().getBlock(at);
            println(String.format("0x%08X block=%s", a, b == null ? "UNMAPPED" : b.getName() + " [" + b.getStart() + ".." + b.getEnd() + "]"));
        }
    }
}
