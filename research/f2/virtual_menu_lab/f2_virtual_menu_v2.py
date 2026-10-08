#!/usr/bin/env python3
"""F2 Virtual Menu Lab V2: ROM-backed registry explorer, read-only."""
import argparse
import hashlib
import json
import struct
import tkinter as tk
from pathlib import Path
from tkinter import ttk, messagebox

BASE = 0xF023CA50
SHA = '85fba8c8ae8161e4c1f8ced7983ec30d48c54ab10e51c69fcdfb900aca220954'
SIZE = 0x185E98
REG = 0xF0378760
RANGES = 0xF037BF54
DESC = 0xF037C08C
ENTRY_COUNT = 895
RANGE_COUNT = 52
B702 = 0xB702
AUDIO = 0x8928
KNOWN = {
    0xB709: ('Racine B709', 'structure prouvée'),
    0xB702: ('Groupe B702 / candidat Multimédia', 'structure prouvée; libellé exact non lié'),
    0x8569: ('Entrée 8569 — famille Audio', 'callback confirmé; libellé inconnu'),
    0x87ED: ('Image Viewer — famille Image', 'identification technique'),
    0x86C0: ('Audio — owner/browser/helper', 'rôle probable, non lecteur natif'),
    0x8928: ('Audio Player natif', 'callback et init confirmés; non énuméré'),
}
CALLBACKS = {0x8569:0x1033E025, 0x87ED:0xF02F3F9D, 0x86C0:0x1033E26D, 0x8928:0x1033D841}
NOTES = {
 0xB709: 'B709.children = B702, AF2A, B707, 8321, B6FE, B6FD, 9639, B700, B705.\nSource: Notion A.48/A.49.',
 0xB702: 'B702.children = 8569, 87ED. Le tableau compact est immédiatement suivi des enfants de B703. Ne jamais incrémenter le compteur seul.\nSource: Notion A.48/A.49 et S13.5A.104.',
 0x8569: 'Callback 1033E025, AUDIO_REG_A. 8569 n’est PAS prouvé comme lanceur direct du lecteur 8928.\nSource: Notion A.50/A.51.',
 0x87ED: 'Callback Image  F02F3F9D ; registration Image Viewer.\nSource: Notion A.50/A.87.',
 0x86C0: 'Parent logique B702, non énuméré par B702.children; callback 1033E26D.\nSource: Notion A.49/A.50.',
 0x8928: 'Application Audio native. Callback 1033D841 -> 1033E815 -> 1033F83C. Parent logique B702 mais absente de tous les tableaux children documentés. Ajout uniquement VIRTUEL.\nSource: Notion A.49/A.50/A.90.',
}

def h(i): return f'0x{i:04X}' if i is not None else 'inconnu'

class Registry:
    def __init__(self, path):
        self.path = Path(path)
        b = self.path.read_bytes()
        if len(b) != SIZE or hashlib.sha256(b).hexdigest() != SHA:
            raise ValueError('ABORT: ZIMAGE size or SHA256 not canonical')
        self.data=b
        def u16(a): return self.read_u16(a)
        def u32(a): return self.read_u32(a)
        if (u32(DESC),u32(DESC+4),u16(DESC+8)) != (REG,RANGES,RANGE_COUNT):
            raise ValueError('ABORT: registry descriptor mismatch')
        self.ranges=[(u16(RANGES+i*6),u16(RANGES+i*6+2),u16(RANGES+i*6+4)) for i in range(RANGE_COUNT)]
        assert all(lo<=hi and baseidx<ENTRY_COUNT for lo,hi,baseidx in self.ranges)
        self.index_by_id={}
        self.id_by_index={}
        for lo,hi,start in self.ranges:
            for pid in range(lo,hi+1):
                index=start+pid-lo
                if pid in self.index_by_id or index in self.id_by_index or not (0<=index<ENTRY_COUNT):
                    raise ValueError('ABORT: overlapping mapping')
                self.index_by_id[pid]=index
                self.id_by_index[index]=pid
        if len(self.index_by_id)!=ENTRY_COUNT-1:
            raise ValueError(f'ABORT: unexpected mapped record count {len(self.index_by_id)}')
        for pid,idx in {0x8313:422,0x8321:436,0x8928:490,0xB702:884,0xB709:891}.items():
            if self.index_by_id.get(pid)!=idx: raise ValueError('ABORT: dense regression')
        self.records={}
        for pid,idx in self.index_by_id.items():
            a=REG+idx*16
            parent=u16(a);count=u16(a+2);ptr=u32(a+12)
            if count>128 or (count and not (BASE <= ptr <= BASE+SIZE-count*2)):
                raise ValueError(f'ABORT: invalid children for {h(pid)}')
            children=[u16(ptr+2*i) for i in range(count)] if count else []
            self.records[pid]={'id':pid,'index':idx,'addr':a,'parent':parent,'count':count,'ptr':ptr,'children':children,'raw':b[a-BASE:a-BASE+16].hex(' ')}
        if self.records[B702]['children'] != [0x8569,0x87ED] or u16(0xF0378724)!=0xA07B:
            raise ValueError('ABORT: B702 packed boundary mismatch')
        if self.records[0xB709]['children'] != [0xB702,0xAF2A,0xB707,0x8321,0xB6FE,0xB6FD,0x9639,0xB700,0xB705]:
            raise ValueError('ABORT: B709 topology regression')
    def read_u16(self,addr):
        off=addr-BASE
        if off<0 or off+2>len(self.data): raise ValueError('out of bounds u16')
        return struct.unpack_from('<H',self.data,off)[0]
    def read_u32(self,addr):
        off=addr-BASE
        if off<0 or off+4>len(self.data): raise ValueError('out of bounds u32')
        return struct.unpack_from('<I',self.data,off)[0]
    def children(self,pid,simulate=False):
        arr=list(self.records[pid]['children'])
        if simulate and pid==B702: arr.append(AUDIO)
        return arr
    def data_summary(self):
        return {'mapped_ids':len(self.records),'dense_records':ENTRY_COUNT,'ranges':len(self.ranges),'b709_children':[h(x) for x in self.children(0xB709)],'b702_original':[h(x) for x in self.children(B702)],'b702_virtual':[h(x) for x in self.children(B702,True)],'audio_callback':h(CALLBACKS[AUDIO]),'rom_mutated':False}

class Gui:
    def __init__(self,reg):
        self.reg=reg
        root=tk.Tk();self.root=root
        root.title('F2 Virtual Menu Lab — Registre + connaissances Notion')
        root.geometry('1090x715');root.minsize(850,540)
        self.sim=tk.BooleanVar(value=False)
        self.query=tk.StringVar()
        bar=ttk.Frame(root,padding=8);bar.pack(fill='x')
        ttk.Label(bar,text='F2 Virtual Menu Lab — modèle ROM, pas émulateur MT6261',font=('Segoe UI',12,'bold')).pack(side='left')
        ttk.Checkbutton(bar,text='Ajouter 8928 virtuellement sous B702',variable=self.sim,command=self.refresh).pack(side='right')
        controls=ttk.Frame(root,padding=(8,0,8,6));controls.pack(fill='x')
        ttk.Button(controls,text='Racine B709',command=lambda:self.open_id(0xB709)).pack(side='left')
        ttk.Button(controls,text='B702',command=lambda:self.open_id(B702)).pack(side='left')
        ttk.Button(controls,text='Audio 8928',command=lambda:self.open_id(AUDIO)).pack(side='left')
        ttk.Label(controls,text='ID hex :').pack(side='left',padx=(20,4))
        ttk.Entry(controls,textvariable=self.query,width=13).pack(side='left')
        ttk.Button(controls,text='Aller',command=self.go).pack(side='left')
        pane=ttk.Panedwindow(root,orient='horizontal');pane.pack(fill='both',expand=True,padx=8,pady=4)
        left=ttk.Frame(pane);right=ttk.Frame(pane)
        pane.add(left,weight=3);pane.add(right,weight=4)
        self.tree=ttk.Treeview(left,columns=('n','relation'),show='tree headings',selectmode='browse')
        self.tree.heading('#0',text='ID / annotation');self.tree.heading('n',text='Enfants');self.tree.heading('relation',text='Lien')
        self.tree.column('#0',width=275);self.tree.column('n',width=52,anchor='center');self.tree.column('relation',width=82)
        self.tree.pack(fill='both',expand=True)
        self.tree.bind('<<TreeviewOpen>>',self.on_expand);self.tree.bind('<<TreeviewSelect>>',self.on_select)
        ttk.Label(right,text='Inspecteur de preuves',font=('Segoe UI',11,'bold')).pack(anchor='w')
        self.details=tk.Text(right,wrap='word',font=('Consolas',10),state='disabled',padx=9,pady=9)
        self.details.pack(fill='both',expand=True)
        footer=ttk.Label(root,text='Données structurales : firmware vérifié SHA256 | Noms partiels : Notion / observation | 8928 ajouté : hypothèse seulement',padding=8)
        footer.pack(fill='x')
        self.populate();self.open_id(B702)
    def title(self,pid):
        label=KNOWN.get(pid,('Libellé non identifié',''))[0]
        return f'{h(pid)} — {label}'
    def insert(self,parent,pid,relation,ancestors=()):
        record=self.reg.records.get(pid)
        nid=self.tree.insert(parent,'end',text=self.title(pid),values=(record['count'] if record else '?',relation))
        if record and record['count'] and pid not in ancestors:self.tree.insert(nid,'end',text='...')
        return nid
    def populate(self):
        self.tree.delete(*self.tree.get_children())
        self.insert('',0xB709,'racine')
        self.insert('',B702,'raccourci')
        self.insert('',0x8928,'app native')
        self.insert('',0x86C0,'parent logique')
        for pid in sorted(self.reg.records):
            if pid in (0xB709,B702,AUDIO,0x86C0):continue
            self.insert('',pid,'registre')
    def get_id(self,item):
        text=self.tree.item(item,'text')
        try:return int(text.split(' ',1)[0],16)
        except ValueError:return None
    def ancestors(self,item):
        acc=[]
        while item:
            p=self.get_id(item)
            if p is not None:acc.append(p)
            item=self.tree.parent(item)
        return tuple(acc)
    def on_expand(self,_evt=None):
        item=self.tree.focus();pid=self.get_id(item)
        if pid not in self.reg.records:return
        children=self.tree.get_children(item)
        if len(children)!=1 or self.tree.item(children[0],'text')!='...':return
        self.tree.delete(children[0]);anc=self.ancestors(item)
        for ch in self.reg.children(pid,self.sim.get()):self.insert(item,ch,'virtuel' if pid==B702 and ch==AUDIO and self.sim.get() else 'énuméré',anc)
    def on_select(self,_evt=None):
        item=self.tree.focus();pid=self.get_id(item)
        if pid is None:return
        r=self.reg.records.get(pid)
        callback=CALLBACKS.get(pid)
        rows=[f'ID PUBLIC : {h(pid)}',f'ANCRAGE : {KNOWN.get(pid,("Nom non prouvé",""))[1]}','']
        if r:
            rows += [f'INDEX DENSE : {r["index"]}',f'RECORD : 0x{r["addr"]:08X}',f'PARENT LOGIQUE : {h(r["parent"])}',f'CHILD_COUNT ROM : {r["count"]}',f'CHILD_PTR ROM : 0x{r["ptr"]:08X}',f'CHILDREN ROM : {", ".join(map(h,r["children"])) or "aucun"}',f'RAW RECORD : {r["raw"]}']
            if pid==B702 and self.sim.get(): rows.append('CHILDREN VIRTUELS : 0x8569, 0x87ED, 0x8928')
        else:rows.append('Absent de la table de mapping')
        if callback:rows.append(f'CALLBACK DOCUMENTÉ : 0x{callback:08X}')
        rows += ['','--- PREUVES NOTION / LIMITES ---',NOTES.get(pid,'Seule la structure de registre a été extraite. Aucun nom de menu, icône, action ou visibilité n’est prouvé pour cet ID.'),'','--- CONTRAINTES ---','Pas d’exécution ARM/Thumb. Pas de rendu LCD original. Pas de lancement MP3. Aucun firmware modifié.','FM Radio : visible sur téléphone, ID interne NON IDENTIFIÉ. Ne pas lui assigner arbitrairement 8569.']
        self.details.config(state='normal');self.details.delete('1.0','end');self.details.insert('1.0','\n'.join(rows));self.details.config(state='disabled')
    def open_id(self,pid):
        for item in self.tree.get_children():
            if self.get_id(item)==pid:
                self.tree.selection_set(item);self.tree.focus(item);self.tree.see(item);self.on_select();return
    def refresh(self):self.populate();self.open_id(B702)
    def go(self):
        try:pid=int(self.query.get().strip().removeprefix('0x'),16)
        except ValueError:return messagebox.showwarning('ID','Saisir un ID hex, ex : B702')
        if pid not in self.reg.records:return messagebox.showinfo('Non trouvé',f'{h(pid)} absent des 894 IDs mappés')
        self.open_id(pid)

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--firmware',type=Path,required=True)
    ap.add_argument('--json',action='store_true')
    args=ap.parse_args();r=Registry(args.firmware)
    if args.json:print(json.dumps(r.data_summary(),indent=2,ensure_ascii=False))
    else:Gui(r).root.mainloop()
if __name__=='__main__':main()
