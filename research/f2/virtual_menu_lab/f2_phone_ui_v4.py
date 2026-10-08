#!/usr/bin/env python3
"""F2 Virtual Menu Lab V4: UI reconstructed from user photographs, offline/read-only.

The GUI does not run native MT6261 software or access phone hardware.
The ROM-backed registry inspector (V2) remains authoritative for binary topology.
"""
import argparse
import subprocess
import sys
import tkinter as tk
from pathlib import Path
from tkinter import ttk

from f2_virtual_menu_v2 import Registry, B702, AUDIO

# LCD graphics below are redrawn approximations, not screenshots/firmware assets.
HOME = (
    ('Disc', 'disc', False), ('Messages', 'message', False), ('Calls', 'phone', False),
    ('Camera', 'camera', True), ('Phonebook', 'contacts', True),
    ('File manager', 'folder', True), ('Organizer', 'organizer', False),
    ('Multimedia', 'multimedia', False), ('Settings', 'settings', False),
)
BLUE = '#0962d8'
TEXT = '#1b2550'
PALE = '#d9e6ff'
WHITE = '#e6f1ff'
LCD_W, LCD_H = 240, 300


class UiModel:
    """Pure navigation model; image/FM representations are mock screens."""
    def __init__(self):
        self.stack = [('home', 4)]
        self.virtual_audio = False
        self.earphones = False
        self.frequency = 98.7  # photographed example, NOT read from a tuner
        self.noted = ''

    @property
    def page(self):
        return self.stack[-1][0]

    @property
    def index(self):
        return self.stack[-1][1]

    @index.setter
    def index(self, value):
        self.stack[-1] = (self.page, value)

    def options(self):
        return {
            'multimedia': ['Image viewer', 'FM radio'] + (['Audio player [virtuel]'] if self.virtual_audio else []),
            'image_options': ['Storage'],
            'file_manager': ['Phone', 'Memory card'],
            'fm_options': ['Channel list', 'Manual input', 'Auto search'],
        }.get(self.page, [])

    def go(self, page, index=0):
        self.stack.append((page, index))
        self.noted = ''

    def back(self):
        if len(self.stack) > 1:
            self.stack.pop()
            self.noted = ''

    def move(self, direction):
        if self.page == 'home':
            self.index = (self.index + direction) % len(HOME)
        else:
            n = len(self.options())
            if n:
                self.index = (self.index + direction) % n

    def enter(self):
        p, i = self.page, self.index
        if p == 'home':
            key = HOME[i][1]
            if key == 'multimedia':
                self.go('multimedia')
            elif key == 'folder':
                self.go('file_manager')
            else:
                # No invented screens/actions for icons not photographed.
                self.go('undocumented', i)
        elif p == 'multimedia':
            self.go(['image', 'fm', 'audio'][i])
        elif p == 'image_options':
            self.go('file_manager')
        elif p == 'fm_options':
            self.go(['fm_channels', 'fm_manual', 'fm_auto'][i])
        elif p == 'file_manager':
            self.go('storage')
        elif p == 'fm':
            self.noted = 'Commandes de radio : démonstration graphique uniquement.'

    def left_softkey(self):
        if self.page == 'image':
            self.go('image_options')
        elif self.page == 'fm':
            self.go('fm_options')
        else:
            self.enter()

    def press_digit(self, digit):
        if self.page == 'home':
            if 1 <= digit <= 9:
                self.index = digit - 1
        else:
            n = len(self.options())
            if 1 <= digit <= n:
                self.index = digit - 1
                self.enter()

    def tune(self, step):
        if self.page == 'fm' and self.earphones:
            self.frequency = round(min(108.0, max(87.5, self.frequency + step)), 1)
            self.noted = 'Fréquence simulée. Aucun accès matériel FM.'


class PhoneUI:
    def __init__(self, registry):
        self.reg = registry
        self.model = UiModel()
        self.root = tk.Tk()
        self.root.title('F2 Virtual Menu Lab V4 — Interface observée sur le téléphone')
        self.root.geometry('1090x830')
        self.root.minsize(820, 710)
        self.left = tk.Frame(self.root, bg='#e1e4ea')
        self.left.pack(side='left', fill='both', expand=False, padx=12, pady=12)
        self.phone = tk.Canvas(self.left, width=460, height=776, bg='#e1e4ea', highlightthickness=0)
        self.phone.pack()
        right = ttk.Frame(self.root, padding=(8, 16, 12, 10))
        right.pack(side='left', fill='both', expand=True)
        ttk.Label(right, text='F2 — Référence photographique', font=('Segoe UI', 17, 'bold')).pack(anchor='w')
        ttk.Label(right, text='Interface reconstruite · pas une émulation MT6261', font=('Segoe UI', 10)).pack(anchor='w', pady=(0, 16))
        self.audio_flag = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text='Ajouter Audio player 0x8928 (uniquement virtuel)', variable=self.audio_flag, command=self.set_audio).pack(anchor='w', pady=3)
        self.ear_flag = tk.BooleanVar(value=False)
        ttk.Checkbutton(right, text='Écouteurs branchés (simulation)', variable=self.ear_flag, command=self.set_earphones).pack(anchor='w', pady=3)
        ttk.Button(right, text='Ouvrir l’explorateur technique V2', command=self.open_explorer).pack(anchor='w', pady=12)
        ttk.Label(right, text='Écran et niveau de preuve', font=('Segoe UI', 12, 'bold')).pack(anchor='w', pady=(8, 6))
        self.details = tk.Text(right, wrap='word', font=('Consolas', 10), relief='groove', padx=10, pady=12)
        self.details.pack(fill='both', expand=True)
        ttk.Label(right, text='Flèches : navigation · Entrée : OK · Échap : Retour · F1 : touche gauche · Chiffres : sélection', wraplength=520).pack(anchor='w', pady=(8, 0))
        self.keys = []
        self.root.bind('<KeyPress>', self.keyboard)
        self.phone.bind('<Button-1>', self.click)
        self.paint()

    def set_audio(self):
        self.model.virtual_audio = self.audio_flag.get()
        if self.model.page == 'multimedia':
            self.model.index = min(self.model.index, len(self.model.options())-1)
        self.paint()

    def set_earphones(self):
        self.model.earphones = self.ear_flag.get()
        self.paint()

    def keyboard(self, event):
        sym = event.keysym
        if sym in ('Up', 'Down', 'Left', 'Right'):
            if self.model.page == 'fm' and self.model.earphones and sym in ('Left', 'Right'):
                self.model.tune(-0.1 if sym == 'Left' else 0.1)
            else:
                delta = {'Up': -3, 'Down': 3, 'Left': -1, 'Right': 1}[sym] if self.model.page == 'home' else (-1 if sym in ('Up', 'Left') else 1)
                self.model.move(delta)
        elif sym in ('Return', 'KP_Enter'):
            self.model.enter()
        elif sym in ('Escape', 'BackSpace'):
            self.model.back()
        elif sym == 'F1':
            self.model.left_softkey()
        elif sym.isdigit() and len(sym) == 1:
            self.model.press_digit(int(sym))
        else:
            return
        self.paint()

    def hotkey(self, x1, y1, x2, y2, fn):
        self.keys.append((x1,y1,x2,y2,fn))

    def click(self, ev):
        for x1,y1,x2,y2,fn in reversed(self.keys):
            if x1 <= ev.x <= x2 and y1 <= ev.y <= y2:
                fn()
                self.paint()
                return

    def rect(self,x1,y1,x2,y2,fill,outline=''):
        self.phone.create_rectangle(self.ax(x1), self.ay(y1), self.ax(x2), self.ay(y2), fill=fill, outline=outline)

    def oval(self,x1,y1,x2,y2,fill='',outline='',width=1):
        self.phone.create_oval(self.ax(x1),self.ay(y1),self.ax(x2),self.ay(y2),fill=fill,outline=outline,width=width)

    def line(self,coords,fill=TEXT,width=1):
        self.phone.create_line(*[self.ax(v) if i%2==0 else self.ay(v) for i,v in enumerate(coords)],fill=fill,width=width)

    def txt(self,x,y,s,size=13,fill=TEXT,bold=True,anchor='center',justify='center'):
        self.phone.create_text(self.ax(x),self.ay(y),text=s,fill=fill,anchor=anchor,justify=justify,font=('Consolas',int(size*1.2),'bold' if bold else 'normal'))

    def ax(self,x): return 84 + 1.21*x
    def ay(self,y): return 102 + 1.21*y

    def gradient(self,y1,y2,start,end):
        def rgb(s):return tuple(int(s[p:p+2],16) for p in (1,3,5))
        a,b=rgb(start),rgb(end)
        for y in range(y1,y2,2):
            t=(y-y1)/max(1,y2-y1)
            col='#'+''.join(f'{round(a[i]*(1-t)+b[i]*t):02x}' for i in range(3))
            self.rect(0,y,LCD_W,min(y+2,y2),col)

    def heading(self,title):
        self.gradient(0,39,'#eef3ff','#b8ccef')
        self.line((0,39,240,39),fill='#94b4e6')
        self.txt(120,19,title,16,'#25458c')

    def footer(self,left='OK',right='Back'):
        self.line((0,262,240,262),fill='#799dd1')
        self.gradient(263,300,'#d5e5ff','#bad1f7')
        self.txt(6,281,left,15,anchor='w')
        self.txt(234,281,right,15,anchor='e')
        self.hotkey(84,102+263*1.21,84+120*1.21,102+300*1.21,self.model.left_softkey)
        self.hotkey(84+120*1.21,102+263*1.21,84+240*1.21,102+300*1.21,self.model.back)

    def list_page(self,title,items,left='OK'):
        self.gradient(0,300,'#d0e1fc','#e8f1ff')
        self.heading(title)
        for i,item in enumerate(items):
            y=41+i*32
            if i==self.model.index:
                self.rect(2,y,237,y+31,'#1775ed')
                self.rect(4,y+1,235,y+3,'#53a4ff')
            self.rect(8,y+3,32,y+29,'#ddeaff' if i==self.model.index else '#d8e9ff',outline='#4c86dd')
            self.txt(20,y+16,str(i+1),15,'#436dc4',bold=False)
            self.txt(36,y+16,item,16,fill='#152351',anchor='w')
        self.footer(left,'Back')

    def icon(self,key,cx,cy,selected=False):
        white='#e1f8ff'; cyan='#87cffb'; deep='#2464cc'
        if selected:
            self.oval(cx-31,cy-30,cx+31,cy+30,'#69bfff','#95e0ff',width=2)
            self.oval(cx-25,cy-24,cx+25,cy+24,'#2872d4','')
        if key=='disc':
            self.oval(cx-20,cy-20,cx+20,cy+20,white)
            self.oval(cx-5,cy-5,cx+5,cy+5,deep)
        elif key=='message':
            self.oval(cx-22,cy-15,cx+16,cy+13,cyan)
            self.oval(cx-7,cy-6,cx+25,cy+20,white)
            self.txt(cx+7,cy+7,'...',11,deep)
        elif key=='phone':
            self.oval(cx-21,cy-21,cx+21,cy+21,white)
            self.txt(cx,cy,'☎',27,deep)
        elif key=='camera':
            self.rect(cx-22,cy-13,cx+22,cy+18,white)
            self.rect(cx-14,cy-18,cx,cy-13,white)
            self.oval(cx-10,cy-10,cx+12,cy+13,cyan,deep,2)
            self.oval(cx-4,cy-4,cx+6,cy+6,deep)
        elif key=='contacts':
            self.rect(cx-18,cy-21,cx+20,cy+23,white)
            self.oval(cx-7,cy-13,cx+7,cy+3,deep)
            self.oval(cx-12,cy+6,cx+12,cy+17,deep)
        elif key=='folder':
            self.rect(cx-22,cy-11,cx+22,cy+18,white)
            self.rect(cx-22,cy-17,cx-5,cy-11,cyan)
        elif key=='organizer':
            for rx in (cx-21,cx+1):
                for ry in (cy-16,cy+4):self.rect(rx,ry,rx+17,ry+16,white)
        elif key=='multimedia':
            self.oval(cx-23,cy-22,cx+23,cy+22,white)
            for rx in (cx-12,cx+2):
                for ry in (cy-11,cy+3):self.rect(rx,ry,rx+11,ry+10,deep)
        elif key=='settings':
            self.txt(cx,cy,'⚙',39,white)

    def home(self):
        self.gradient(0,300,'#0a8ceb','#0327b3')
        self.rect(0,0,240,40,'#0e92ed')
        label=HOME[self.model.index][0]
        self.txt(120,20,label,16,WHITE)
        for i,(_,key,_) in enumerate(HOME):
            cx=47+(i%3)*73
            cy=82+(i//3)*66
            self.icon(key,cx,cy,i==self.model.index)
        self.rect(0,261,240,300,'#1978e4')
        self.line((0,261,240,261),fill='#8fc7ff')
        self.txt(6,280,'OK',15,WHITE,anchor='w')
        self.txt(234,280,'Back',15,WHITE,anchor='e')
        self.hotkey(84,102+261*1.21,84+120*1.21,102+300*1.21,self.model.left_softkey)
        self.hotkey(84+120*1.21,102+261*1.21,84+240*1.21,102+300*1.21,self.model.back)
        for i in range(9):
            x=84+(10+(i%3)*73)*1.21
            y=102+(49+(i//3)*66)*1.21
            def select(j=i):
                self.model.index=j
                self.model.enter()
            self.hotkey(x,y,x+67*1.21,y+61*1.21,select)

    def popup(self, title, msg):
        self.gradient(0,300,'#b6c9fa','#628fe3')
        self.heading(title)
        self.rect(18,48,223,249,'#a0bdeb',outline='#e6eeff')
        self.rect(24,54,217,242,'#d8e6ff',outline='#779ce0')
        self.txt(120,144,msg,16)
        self.footer('Options','Back')

    def fm(self):
        if not self.model.earphones:
            self.popup('FM radio','Please plug\nin earphone')
            return
        self.gradient(0,300,'#d0ddf7','#e0e9fc')
        self.heading('FM radio')
        self.txt(45,58,'87.5',14)
        self.txt(201,58,'108',14)
        self.line((29,77,212,77),'#3756a5',2)
        for step in range(22):
            x=34+step*8
            self.line((x,69 if step%5==0 else 73,x,79),'#5879bd',1)
        tri=round(34+(self.model.frequency-87.5)/(108-87.5)*168)
        self.phone.create_polygon(self.ax(tri)-7,self.ay(86),self.ax(tri)+7,self.ay(86),self.ax(tri),self.ay(80),fill=BLUE)
        self.txt(120,125,f'{self.model.frequency:.1f}',20)
        self.txt(120,156,'FM radio',16)
        self.rect(98,195,145,215,'#d5e7ff',outline='#7497cf')
        self.txt(121,205,'▶▮',12,'#4272c3')
        for x,mark in [(62,'◀◀'),(183,'▶▶')]:
            self.rect(x-20,217,x+20,237,'#b2c9ed')
            self.txt(x,227,mark,11,'#4268b0')
        self.rect(99,218,144,240,'#d7e8fc',outline='#5b84c6')
        self.txt(120,230,'⏻',14,'#4272c3')
        self.rect(98,242,145,258,'#d5e7ff',outline='#7397ce')
        self.txt(121,249,'|◀',11,'#4272c3')
        for x,h in [(193,3),(201,5),(209,8),(217,11)]:self.rect(x,255-h,x+5,255,BLUE)
        self.footer('Options','Back')

    def simple_message(self,title,msg,left='OK'):
        self.gradient(0,300,'#cbdcfc','#e6efff')
        self.heading(title)
        self.txt(120,145,msg,16)
        self.footer(left,'Back')

    def render_page(self):
        p=self.model.page
        if p=='home':self.home()
        elif p=='multimedia':self.list_page('Multimedia',self.model.options())
        elif p=='image':self.simple_message('Image viewer','No files','Options')
        elif p=='image_options':self.list_page('Options',self.model.options(),'Select')
        elif p=='file_manager':self.list_page('File manager',self.model.options())
        elif p=='fm':self.fm()
        elif p=='fm_options':self.list_page('Options',self.model.options(),'Select')
        elif p=='audio':self.simple_message('Audio player','Virtual 0x8928\nNo native execution')
        elif p=='undocumented':self.simple_message(HOME[self.model.index if len(self.model.stack)==1 else self.model.stack[-1][1]][0],'Screen not documented')
        elif p=='storage':self.simple_message('Storage','Content not observed')
        elif p=='fm_manual':self.simple_message('Manual input','Not documented')
        elif p=='fm_channels':self.simple_message('Channel list','Not documented')
        elif p=='fm_auto':self.simple_message('Auto search','No radio scan performed')
        else:self.simple_message('Unknown','Not documented')

    def paint(self):
        c=self.phone
        c.delete('all');self.keys=[]
        c.create_rectangle(34,25,426,757,fill='#111b2d',outline='#0e1425',width=4)
        c.create_arc(34,25,426,125,start=0,extent=180,fill='#111b2d',outline='#111b2d')
        c.create_text(230,76,text='F2',font=('Segoe UI',14,'bold'),fill='#222d45')
        c.create_rectangle(76,95,386,474,fill='#08111c',outline='#253047',width=4)
        self.render_page()
        c.create_text(230,490,text='F2',font=('Segoe UI',23,'bold'),fill='#273249')
        # soft keys, phone buttons, central D-pad and keypad
        for x in (133,330):
            c.create_line(x-23,530,x+23,530,fill='#e4efb6',width=5,capstyle='round')
        self.hotkey(82,510,191,550,self.model.left_softkey)
        self.hotkey(275,510,382,550,self.model.back)
        c.create_oval(160,540,299,673,fill='#152238',outline='#293851',width=3)
        c.create_oval(186,566,273,646,fill='#1b2940',outline='#263c62',width=2)
        self.hotkey(195,553,270,579,lambda:self.model.move(-3 if self.model.page=='home' else -1))
        self.hotkey(195,634,270,661,lambda:self.model.move(3 if self.model.page=='home' else 1))
        self.hotkey(165,582,196,631,lambda:self.model.move(-1))
        self.hotkey(274,582,302,631,lambda:self.model.move(1))
        self.hotkey(196,580,272,629,self.model.enter)
        c.create_text(113,590,text='☎',font=('Segoe UI',23),fill='#39b766')
        c.create_text(344,590,text='☎',font=('Segoe UI',23),fill='#e64a62')
        for row,triplet in enumerate((('1','2 ABC','3 DEF'),('4 GHI','5 JKL','6 MNO'),('7 PQRS','8 TUV','9 WXYZ'))):
            for col,lab in enumerate(triplet):
                x=121+col*109;y=683+row*27
                c.create_text(x,y,text=lab,font=('Segoe UI',11),fill='#c9d3c2')
                number=int(lab[0]);self.hotkey(x-40,y-12,x+40,y+13,lambda n=number:self.model.press_digit(n))
        self.evidence()

    def evidence(self):
        m=self.model
        lines=[f'PAGE : {m.page}',f'MODE : {"Audio virtuel activé" if m.virtual_audio else "Firmware original"}', '', 'PHOTOGRAPHIES UTILISATEUR — OCTOBRE 2026', '']
        if m.page=='home':
            lines+=['IMG_0833 / IMG_0834 : grille 3×3, fond bleu,', 'titre de l’icône sélectionnée, OK / Back.', '','Libellés prouvés à la sélection : Camera, Phonebook.','Les autres icônes sont reproduites graphiquement,','mais tous leurs noms/actions ne sont pas prouvés.', 'Multimedia sur grille : position indicative.']
        elif m.page=='multimedia':
            lines+=['IMG_0836 / IMG_0840 : Multimedia', '1 Image viewer', '2 FM radio', 'Sélection bleue, chiffres encadrés, fond clair.', '', 'REGISTRE : B702.children = [0x8569, 0x87ED]', 'Image Viewer : registration 0x87ED → F02F3F9D.', 'FM radio : identifiant ROM non identifié.', 'Aucun lien direct arbitraire FM ↔ 0x8569.', 'Audio 0x8928 absent des photos et de B702.children.']
        elif m.page=='image':
            lines+=['IMG_0837 : titre Image viewer, No files,', 'Options / Back.', 'ROM : callback Image Viewer F02F3F9D.', 'Aucun moteur d’images réel exécuté.']
        elif m.page=='image_options':lines+=['IMG_0838 : Options > 1 Storage.', 'Touches Select / Back.']
        elif m.page=='file_manager':lines+=['IMG_0839 : File manager, Phone, Memory card.', 'Pas d’accès au stockage réel dans la maquette.']
        elif m.page=='fm':
            lines+=['IMG_0841 : Please plug in earphone.', 'IMG_0842 : plage 87.5—108, 98.7 MHz,', 'contrôles, Options / Back.', '98.7 est la valeur photographiée uniquement.', f'Écouteurs simulés : {m.earphones}', 'Pas de tuner ni de détection jack.']
        elif m.page=='fm_options':lines+=['IMG_0843 : Options :', '1 Channel list', '2 Manual input', '3 Auto search.']
        elif m.page=='audio':lines+=['AJOUT HYPOTHÉTIQUE : 0x8928', 'Callback 0x1033D841 → 0x1033E815.', 'Absent du menu original.', 'Pas d’exécution native, pas de MP3.']
        else:lines+=['Écran non photographié.', 'Visuel de remplacement documentaire.']
        if m.noted:lines+=['',m.noted]
        lines+=['', 'INTERDICTIONS : aucune écriture firmware,', 'aucun accès COM/USB, aucune commande MTK.', 'Les photographies elles-mêmes ne sont pas', 'embarquées dans cette application.']
        self.details.delete('1.0','end')
        self.details.insert('1.0','\n'.join(lines))

    def open_explorer(self):
        path=Path(__file__).with_name('f2_virtual_menu_v2.py')
        subprocess.Popen([sys.executable,'-B',str(path),'--firmware',str(self.reg.path)])


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--firmware',required=True,type=Path)
    parser.add_argument('--verify',action='store_true')
    args=parser.parse_args()
    registry=Registry(args.firmware)
    if args.verify:
        assert registry.records[B702]['children']==[0x8569,0x87ED]
        assert registry.records[0xB709]['children'][0]==B702
        print('V4 PASS — canonical ROM, menu topology and photo-backed UI model. READ ONLY.')
    else:
        PhoneUI(registry).root.mainloop()


if __name__=='__main__':main()
