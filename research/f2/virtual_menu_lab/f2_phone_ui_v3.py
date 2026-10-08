#!/usr/bin/env python3
"""F2 phone-like presentation for documented interface: not MT6261 hardware emulation."""
import argparse
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from f2_virtual_menu_v2 import Registry, B702, AUDIO, CALLBACKS, KNOWN, NOTES, h

NAVY='#192435'; LCD='#e4ecdd'; INK='#233727'; HI='#527e65'; PALE='#cbd9c4'

class PhoneUI:
    def __init__(self, registry):
        self.reg=registry; self.root=tk.Tk();self.root.title('F2 Virtual Menu Lab V3 — Maquette téléphone + preuves')
        self.root.geometry('1020x760');self.root.minsize(800,640)
        self.virtual=tk.BooleanVar(value=False);self.stack=['home'];self.pos=0;self.screen_items=[]
        outer=ttk.Panedwindow(self.root,orient='horizontal');outer.pack(fill='both',expand=True,padx=12,pady=12)
        phone_area=tk.Frame(outer,bg='#edf0f2');outer.add(phone_area,weight=2)
        inspect=ttk.Frame(outer,padding=10);outer.add(inspect,weight=3)
        shell=tk.Frame(phone_area,bg=NAVY,bd=4,relief='ridge');shell.pack(pady=8,padx=35,fill='both',expand=True)
        tk.Label(shell,text='ALTICE   •   F2',bg=NAVY,fg='white',font=('Segoe UI',12,'bold')).pack(pady=(18,10))
        frame=tk.Frame(shell,bg='#0e1925',padx=9,pady=9);frame.pack(padx=18,fill='x')
        self.lcd=tk.Canvas(frame,width=278,height=277,bg=LCD,highlightthickness=0)
        self.lcd.pack()
        keys=tk.Frame(shell,bg=NAVY);keys.pack(pady=13)
        def key(text,row,col,fn,width=7):
            tk.Button(keys,text=text,command=fn,width=width,height=2,bg='#d9dde2',relief='raised',font=('Segoe UI',9,'bold')).grid(row=row,column=col,padx=4,pady=3)
        key('Menu',0,0,lambda:self.enter());key('▲',0,1,lambda:self.move(-1));key('Retour',0,2,self.back)
        key('◀',1,0,self.back);key('OK',1,1,self.enter);key('▶',1,2,self.enter)
        key('1',2,0,lambda:self.select_number(0));key('▼',2,1,lambda:self.move(1));key('3',2,2,lambda:self.select_number(2))
        key('*',3,0,lambda:None);key('2',3,1,lambda:self.select_number(1));key('#',3,2,lambda:None)
        tk.Label(shell,text='Maquette visuelle — pas un rendu LCD extrait',bg=NAVY,fg='#bfc8d5',font=('Segoe UI',8)).pack(pady=6)
        ttk.Label(inspect,text='Interface documentée et preuves',font=('Segoe UI',14,'bold')).pack(anchor='w')
        ttk.Label(inspect,text='ROM vérifiée SHA256 · Identifiants issus du registre · UI indicative',wraplength=450).pack(anchor='w',pady=(2,10))
        ttk.Checkbutton(inspect,text='Simuler l’ajout de 8928 à B702 (sans patch)',variable=self.virtual,command=self.redraw).pack(anchor='w')
        ttk.Button(inspect,text='Voir l’explorateur complet (V2)',command=self.open_explorer).pack(anchor='w',pady=8)
        ttk.Label(inspect,text='Inspecteur de l’écran courant',font=('Segoe UI',11,'bold')).pack(anchor='w',pady=(6,4))
        self.details=tk.Text(inspect,font=('Consolas',10),wrap='word',padx=10,pady=10)
        self.details.pack(fill='both',expand=True)
        self.detail_footer=ttk.Label(inspect,text='Image Viewer et FM : présence observée sur le téléphone, mais la correspondance FM↔ID reste inconnue.',wraplength=430)
        self.detail_footer.pack(fill='x',pady=9)
        self.root.bind('<Up>',lambda _e:self.move(-1));self.root.bind('<Down>',lambda _e:self.move(1))
        self.root.bind('<Return>',lambda _e:self.enter());self.root.bind('<BackSpace>',lambda _e:self.back())
        self.root.bind('<Escape>',lambda _e:self.back());self.root.bind('<Left>',lambda _e:self.back());self.root.bind('<Right>',lambda _e:self.enter())
        self.redraw()
    def current(self):return self.stack[-1]
    def items(self):
        s=self.current()
        if s=='home':return [('Multimédia (observé)',('menu','multimedia')),('Explorateur ROM B709',('menu','B709')),('Documentation',('menu','about'))]
        if s=='multimedia':return [('Image Viewer (observé)',('page','image')),('Radio FM (observée)',('page','fm'))]+([('Audio Player 8928 (virtuel)',('page','audio'))] if self.virtual.get() else [])+[('Données brutes B702',('menu','B702'))]
        if s in ('B709','B702'):
            p=int(s,16);return [(f'{h(i)}  {KNOWN.get(i,("ID sans libellé",))[0]}',('record',i)) for i in self.reg.children(p,self.virtual.get())]
        return []
    def draw(self):
        c=self.lcd;c.delete('all');w=278
        c.create_rectangle(0,0,w,24,fill=HI,outline='');c.create_text(8,12,text='F2  ▣',anchor='w',fill='white',font=('Arial',10,'bold'))
        c.create_text(w-8,12,text='▮▮  100%',anchor='e',fill='white',font=('Arial',9))
        mode=self.current();heading={'home':'Menu principal (maquette)','multimedia':'Multimédia','B709':'Registre B709','B702':'Registre B702','image':'Image Viewer','fm':'Radio FM','audio':'Audio Player','about':'Documentation'}.get(mode,str(mode))
        c.create_text(w/2,43,text=heading,fill=INK,font=('Arial',13,'bold'))
        items=self.items();self.screen_items=items
        if items:
            self.pos=min(self.pos,len(items)-1)
            begin=max(0,min(self.pos-2,max(0,len(items)-5)))
            for j in range(begin,min(begin+5,len(items))):
                y=69+(j-begin)*36
                if j==self.pos:c.create_rectangle(9,y-11,269,y+21,fill=HI,outline='')
                c.create_text(17,y+4,text=items[j][0][:32],anchor='w',fill='white' if j==self.pos else INK,font=('Arial',9,'bold' if j==self.pos else 'normal'))
        else:
            msg={'image':'Visualiseur documenté\nCallback F02F3F9D\nAucune photo chargée','fm':'Radio FM présente sur le F2\nID interne encore inconnu\nPas de tuner simulé','audio':'Application native 8928\n1033D841 → 1033E815\nNon lancée ici','about':'Structure ROM vérifiée\nUI, polices et icônes indicatives\nPas d’exécution ARM/Thumb'}.get(mode,'Aucun enfant')
            c.create_text(w/2,132,text=msg,fill=INK,justify='center',font=('Arial',10))
        c.create_rectangle(0,247,w,277,fill=PALE,outline='')
        c.create_text(9,262,text='Retour',anchor='w',fill=INK,font=('Arial',9,'bold'))
        c.create_text(w-9,262,text='Ouvrir' if items else 'Info',anchor='e',fill=INK,font=('Arial',9,'bold'))
        self.inspect()
    def inspect(self):
        s=self.current();items=self.screen_items
        lines=[f'ÉCRAN : {s}',f'MODE : {"Ajout virtuel 8928" if self.virtual.get() else "Original"}','']
        if s=='multimedia':
            lines+=['AFFICHAGE : observation utilisateur + annotations','- Image Viewer : visible sur téléphone','- Radio FM : visible sur téléphone','- Audio 8928 : absent de l’écran réel','', 'ATTENTION : les deux premiers éléments sont des observations,','pas un mapping vérifié vers les IDs 8569 / 87ED.']
        elif s in ('B702','B709'):
            p=int(s,16);r=self.reg.records[p];lines += [f'RECORD : 0x{r["addr"]:08X}',f'PARENT : {h(r["parent"])}',f'CHILD_COUNT : {r["count"]}',f'CHILD_PTR : 0x{r["ptr"]:08X}',f'ENFANTS ROM : {", ".join(h(x) for x in r["children"])}']
        elif s=='image':lines+=['Enregistrement technique : 87ED','Callback : F02F3F9D','Le moteur Image Viewer réel n’est pas exécuté.']
        elif s=='fm':lines+=['Observation : module FM visible dans Multimédia.','Identifiant interne FM : NON ÉTABLI.','Aucun signal radio ou commande matérielle simulés.']
        elif s=='audio':lines+=['CANDIDAT VIRTUEL uniquement','Application native : 8928','Callback : 1033D841','Initialisation : 1033E815 → 1033F83C','Non énumérée actuellement par B702.']
        elif s=='home':lines+=['Le menu principal complet et ses ressources graphiques','ne sont pas encore reconstruits depuis le firmware.','', 'Choisir Multimédia pour l’interface observée,','ou B709 pour la hiérarchie prouvée.']
        if items:
            lines+=['',f'SÉLECTION : {items[self.pos][0]}']
            typ,val=items[self.pos][1]
            if typ=='record':
                r=self.reg.records.get(val)
                lines += [f'ID : {h(val)}',f'Callback documenté : {h(CALLBACKS[val]) if val in CALLBACKS else "inconnu"}', NOTES.get(val,'Aucun rôle UI connu pour cet ID.')]
        lines+=['','SOURCE : Notion S13.5A.47–50, A.87–90 et','observations utilisateur.','', 'AUCUN FLASH · AUCUN PATCH · AUCUNE ÉMULATION CPU']
        self.details.delete('1.0','end');self.details.insert('1.0','\n'.join(lines))
    def redraw(self):self.pos=0;self.draw()
    def move(self,step):
        if self.items():self.pos=(self.pos+step)%len(self.items());self.draw()
    def enter(self):
        items=self.items()
        if not items:return
        kind,value=items[self.pos][1]
        if kind=='record':
            if value in (B702,0xB709) and self.reg.children(value,self.virtual.get()):value=f'{value:04X}'
            else:return messagebox.showinfo('ID du registre',f'{h(value)} : la fonction d’ouverture native n’est pas prouvée.\nConsultez l’inspecteur.')
        self.stack.append(value);self.pos=0;self.draw()
    def back(self):
        if len(self.stack)>1:self.stack.pop();self.pos=0;self.draw()
    def select_number(self,i):
        if i<len(self.items()):self.pos=i;self.draw()
    def open_explorer(self):
        from f2_virtual_menu_v2 import Gui
        # V2 owns its own Tk root; run separate process to avoid two Tk roots in one process.
        import subprocess,sys
        subprocess.Popen([sys.executable,'-B',str(Path(__file__).with_name('f2_virtual_menu_v2.py')),'--firmware',str(self.reg.path)])

def main():
    p=argparse.ArgumentParser();p.add_argument('--firmware',type=Path,required=True);p.add_argument('--verify',action='store_true');a=p.parse_args()
    reg=Registry(a.firmware)
    if a.verify:
        assert reg.records[B702]['children']==[0x8569,0x87ED]
        assert reg.records[0xB709]['children'][0]==B702
        print('V3 PASS: firmware SHA256, B709/B702, UI navigation model; no writes')
    else:PhoneUI(reg).root.mainloop()
if __name__=='__main__':main()
