"""Pinned Altice ABI, format and dispatch evidence; no device I/O or patching."""
import json
import struct
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB
from analyze_audio_paths import load_images, read, require, disasm, EXPECTED, GHIDRA_REPORTS

def main():
    images = load_images()
    checks = []
    anchors = {
        0x10303be4:'08218420', 0x10303bf0:'84220021',
        0x1028d23e:'4968', 0x1028d250:'042270f01ce9',
        0x1028d31a:'6069019a0699002801d0134800e00020b0470028a862',
        0x1028d34e:'6069e867a069803528600020',
        0x1028d39c:'407b002801d00120',
        0x1028d3c4:'a06af021095888470600c82802d11e206873',
        0x1028d3ea:'300071f03cf9',
        0x1035825c:'00280ad1', 0x1035826e:'a3f7a2ef',
        0x103582c6:'1b482063',
        0x1035fb2c:'0320', 0x1035fb34:'b6f7b8fb',
        0x1035fb40:'8847', 0x1035fb5e:'05209bf7dcef',
        0x1035fb70:'8847', 0x1035fb7a:'9847', 0x1035fb82:'9df7ece8',
        0xf02ae62c:'9847', 0xf02ae640:'8847',
        0x1029d3ae:'00207047', 0x1029d3b6:'17f0a1f8',
        0x102b453e:'55f015fa', 0x1030999a:'0d212030c171', 0x103099ec:'2000f8bd',
        0x1028d4c4:'806af82109588847',
        0x1029d3c6:'002805d0ff210931095888470500a662',
        0x1029d3f8:'20002c3060f04ae83e73',
        0x1028d0d4:'08b50028009004d0034a04a168466ff0d4ef002008bd',
        0x102fe668:'c83800b5030017f5b2ea',
    }
    for address, expected in anchors.items():
        require(read(images,address,len(bytes.fromhex(expected))).hex()==expected,f'Byte mismatch {address:#x}')
        checks.append(dict(address=hex(address),bytes=expected))
    callbacks = [0x1028d230,0x1029d3bc,0x1028d394,0x1028d4c0,0x1028d378,
                 0x1028d41c,0x1028d43a,0x1028d114,0x1028d0d4]
    md = Cs(CS_ARCH_ARM,CS_MODE_THUMB)
    for index, target in enumerate(callbacks):
        require(read(images,0x10303c50+4*index,4)==struct.pack('<I',target|1),'Callback literal')
        ins = list(md.disasm(read(images,0x10303bf8+4*index,4),0x10303bf8+4*index))
        require(len(ins)==2 and ins[0].mnemonic=='ldr' and ins[1].mnemonic=='str','Callback initialization')
        require(ins[1].op_str == ('r0, [r4]' if index==0 else f'r0, [r4, #{hex(4*index) if 4*index>=10 else 4*index}]'), 'Callback offset')
    require(read(images,0x10358334,4)==struct.pack('<I',0x1035fb01),'MHdl.Play')
    veneers={0x102fcd5c:0xf02ae5f0,0x102fcfbc:0xf02dbff6,0x102fcb2c:0xf02e619c,
             0x102fc564:0xf02e6180,0x102fcfdc:0xf02aea88,0x102fbb1c:0xf02e3f48,
             0x102fc1b4:0xf02e1b00}
    for address,target in veneers.items():
        require(read(images,address,8)==struct.pack('<II',0xe51ff004,target|1),f'Veneer {address:#x}')
    formats=[('.VM',0xf02ade6c,0xf02adda4,2),('.IMY',0xf02ade74,0xf02addb6,18),
             ('.MID',0xf02ade80,0xf02ade62,17),('.WAV',0xf02ade8c,0xf02addd2,13),
             ('.PCM',0xf02ade98,0xf02adde2,7),('.DVI',0xf02adea4,0xf02addf2,11),
             ('.MP3',0xf02adeb0,0xf02ade02,5),('.MP2',0xf02adebc,0xf02ade12,32),
             ('.AMR',0xf02adec8,0xf02ade22,3),('.AAC',0xf02aded4,0xf02ade32,6),
             ('.JPG',0xf02adee0,0xf02ade42,110),('.MIDI',0xf02adeec,0xf02ade62,17)]
    for suffix,address,result,code in formats:
        require(read(images,address,2*(len(suffix)+1))==(suffix+'\0').encode('utf-16le'),'Suffix '+suffix)
        require(read(images,result,2)==struct.pack('<H',0x2000|code),'Format code '+suffix)
    table = read(images,0x1028d29e,20)
    require(table.hex()=='110c0c0c1d37252914141414140c272727273700','Open switch table')
    require(read(images,0x10015bd8,4)==struct.pack('<I',0x70008c68),'External switch helper')
    dispatch={2:(0x1028d2b6,0x1029d3ae),3:(0x1028d2d8,0x10357420),
              5:(0x1028d2e8,0x10358254),6:(0x1028d2f0,0x10357368),
              7:(0x1028d2c6,0x1029cf68),11:(0x1028d2c6,0x1029cf68),13:(0x1028d2ec,0x1029d3b2)}
    for code,(block,handler) in dispatch.items():
        require(0x1028d29e+2*table[1+code]==block,'Inferred switch8 case')
    for address,value in [(0x1028d35c,0x1029d3af),(0x1028d360,0x1029cf69),
        (0x1028d364,0x10357421),(0x1028d368,0x10358255),(0x1028d36c,0x1029d3b3),(0x1028d370,0x10357369)]:
        require(read(images,address,4)==struct.pack('<I',value),'Handler literal')
    report=dict(status='PASS',hashes=EXPECTED,checks=checks,
        callbacks=[dict(offset=hex(i*4),target=hex(t)) for i,t in enumerate(callbacks)],
        formats=[dict(suffix=s,address=hex(a),code=c) for s,a,_,c in formats],
        dispatch_inferred={str(c):dict(block=hex(b),handler=hex(h)) for c,(b,h) in dispatch.items()},
        limitations=['switch8 body unavailable: table interpretation remains inferred.',
            'Null callback accepted but selects alternate DAF construction: playback not proven.',
            'AudioDrain indirect component identities and hardware route need separate verification.',
            'Public Play status mapping not proven; never use guessed success codes.',
            'No playback or cleanup timing validated on a handset.'])
    (GHIDRA_REPORTS/'minimal_player_abi.json').write_text(json.dumps(report,indent=2),encoding='utf-8')
    ranges=[(0x10303be0,0x46),(0x1028d230,0x6e),(0x1028d2b2,0xaa),(0x1028d394,0x5e),
        (0x1028d4c0,0x34),(0x1029d3bc,0x4e),(0x1028d0d4,0x16),(0x10358254,0x98),
        (0x1035fb00,0x9c),(0xf02ae5f0,0x54),(0xf02e1b00,0x64),
        (0xf02add64,0x108),(0x1029d3ae,0xe),(0x102b44fc,0x48),(0x1030996c,0x84)]
    (GHIDRA_REPORTS/'minimal_player_abi_disasm.txt').write_text('\n\n'.join(disasm(images,a,n) for a,n in ranges),encoding='utf-8')
    print(f'PASS: {len(checks)} anchors, 9 interface callbacks, 12 media suffixes, 7 inferred dispatch cases; limitations retained')

if __name__=='__main__':
    main()
