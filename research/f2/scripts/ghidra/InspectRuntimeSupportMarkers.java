// Read-only search for MRE/VXP/application-runtime markers and their code xrefs.
//@category ARM
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.*;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.symbol.*;
import ghidra.program.model.listing.*;
import java.nio.charset.StandardCharsets;

public class InspectRuntimeSupportMarkers extends GhidraScript {
  void search(byte[] needle,String label,Memory mem,Address min,Address max) throws Exception {
    Address cur=min; int hits=0;
    while(cur!=null && cur.compareTo(max)<=0 && !monitor.isCancelled()) {
      Address hit=mem.findBytes(cur,max,needle,null,true,monitor);
      if(hit==null) break;
      hits++; println("\n"+label+" @ "+hit);
      ReferenceIterator ri=currentProgram.getReferenceManager().getReferencesTo(hit); int n=0;
      while(ri.hasNext()) { Reference r=ri.next(); Function f=getFunctionContaining(r.getFromAddress()); println("XREF "+r.getFromAddress()+" caller="+(f==null?"?":f.getEntryPoint())); n++; }
      if(n==0) println("XREF none");
      cur=hit.add(1);
    }
    if(hits==0) println("\n"+label+": ABSENT");
  }
  byte[] utf16(String s) { byte[] a=new byte[s.length()*2]; for(int i=0;i<s.length();i++){a[i*2]=(byte)s.charAt(i); a[i*2+1]=0;} return a; }
  public void run() throws Exception {
    Memory m=currentProgram.getMemory(); Address lo=m.getMinAddress(),hi=m.getMaxAddress();
    for(String s:new String[]{"[MRE VERSION]",".vxp","VXP","MRE API","MRE app","MRE APP","Java","J2ME","appdb","@mre"}) {
      search(s.getBytes(StandardCharsets.US_ASCII),"ASCII "+s,m,lo,hi);
      if(s.length()<=16) search(utf16(s),"UTF16 "+s,m,lo,hi);
    }
  }
}
