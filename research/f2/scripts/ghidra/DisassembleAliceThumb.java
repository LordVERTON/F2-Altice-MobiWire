// Force ARM Thumb disassembly from the start of a raw ALICE image.
//@category ARM

import ghidra.app.cmd.disassemble.ArmDisassembleCommand;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Processor;
import ghidra.util.Msg;

public class DisassembleAliceThumb extends GhidraScript {
    @Override
    public void run() throws Exception {
        Processor arm = Processor.findOrPossiblyCreateProcessor("ARM");
        if (currentProgram == null ||
            !currentProgram.getLanguage().getProcessor().equals(arm)) {
            Msg.showError(this, null, "ALICE", "Le programme n'est pas ARM.");
            return;
        }

        // The ALICE base is fixed by its own header. Do not use memory.getMinAddress():
        // a combined ROM+ALICE program has the ROM block before ALICE.
        Address start = toAddr(0x101812C4L);
        println("ALICE Thumb start: " + start);

        // ARM-specific command: true = Thumb mode.
        ArmDisassembleCommand cmd = new ArmDisassembleCommand(start, null, true);
        boolean ok = cmd.applyTo(currentProgram, monitor);

        println("Thumb disassembly result: " + ok);
    }
}
