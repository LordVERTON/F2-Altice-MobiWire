#!/usr/bin/env python3
"""F2 Virtual Menu Lab V5: photo-grounded UI + ROM-backed read-only registry.

Requires the V4 phone shell and V2 ROM Registry in the same folder.
No flashing, USB/COM communication, camera, SMS, tuner, or native binary execution.
"""
from __future__ import annotations

import argparse
import calendar
import json
import sys
from pathlib import Path

import f2_phone_ui_v4 as v4
from f2_virtual_menu_v2 import B702, AUDIO, Registry
from f2_registration_bridge import load_layers, menu_items, ui_rom_binding

DIR = Path(__file__).resolve().parent
UI_FILE = DIR / 'ui_observed_registry.json'
ROM_FILE = DIR / 'rom_proven_registry.json'


def load_contract(ui_path=UI_FILE, rom_path=ROM_FILE, overlay_path=DIR / 'research_overlay_registry.json'):
    """Read and verify three independent evidence layers (UI, ROM, research)."""
    return load_layers(ui_path, rom_path, overlay_path)


def validate_against_registry(registry, rom):
    # Registry() has already verified canonical length, sha256, descriptor,
    # packed child boundary, 52 ranges, 894 mappings and root B709 children.
    def hx(v): return f'0x{v:04X}'
    if [hx(v) for v in registry.records[B702]['children']] != rom['topology']['multimedia_children_rom']:
        raise ValueError('B702 firmware/JSON divergence')
    if [hx(v) for v in registry.records[0xB709]['children']] != rom['topology']['root_children']:
        raise ValueError('B709 firmware/JSON divergence')
    if registry.records[AUDIO]['parent'] != B702:
        raise ValueError('Audio logical owner mismatch')
    if registry.records[AUDIO]['index'] != rom['id_bindings']['audio_player']['dense_index']:
        raise ValueError('Audio dense-index mismatch')
    if any(AUDIO in record['children'] for record in registry.records.values()):
        raise ValueError('Audio unexpectedly enumerated in firmware')
    if registry.read_u16(0xF0378724) != int(rom['topology']['packed_next_u16'], 16):
        raise ValueError('B702 packed boundary changed')
    if len(registry.records) != rom['registry']['mapped_ids']:
        raise ValueError('Mapped records count mismatch')
    return {'canonical_zimage_valid': True,
            'mapped_ids': len(registry.records),
            'b702_original': [hx(v) for v in registry.records[B702]['children']],
            'b709_count': len(registry.records[0xB709]['children']),
            'audio_id': hx(AUDIO), 'audio_enumerated': False,
            'fm_id': None, 'writes_performed': False}


class UiModelV5:
    """Deterministic UI reconstruction. Navigation to undocumented views is labeled."""
    def __init__(self, manifest, overlay):
        self.manifest = manifest
        self.overlay = overlay
        self.stack = [('home', 4, '')]  # 4 = Phonebook, photographed highlight
        self.virtual_audio = False
        self.earphones = False
        self.frequency = 98.7  # Screenshot example, not hardware tuner state
        self.torch_on = False
        self.calculator_value = '0'
        self.noted = ''

    @property
    def page(self): return self.stack[-1][0]

    @property
    def index(self): return self.stack[-1][1]

    @index.setter
    def index(self, value):
        page, _, title = self.stack[-1]
        self.stack[-1] = (page, value, title)

    @property
    def subtitle(self): return self.stack[-1][2]

    def screen(self): return self.manifest['screens'].get(self.page)

    def items(self):
        return menu_items(self.manifest, self.overlay, self.page, self.virtual_audio)

    def options(self): return [x['label'] for x in self.items()]

    def go(self, page, index=None, title=''):
        if index is None:
            index = 1 if page == 'profiles' else 0  # Silent highlighted in photo
        self.stack.append((page, index, title))
        self.noted = ''

    def back(self):
        if len(self.stack) > 1:
            self.stack.pop()
            self.noted = ''

    def move(self, direction):
        n = len(self.items())
        if n:
            self.index = (self.index + direction) % n

    def enter(self):
        rows = self.items()
        if 0 <= self.index < len(rows):
            item = rows[self.index]
            target = item.get('target')
            if target:
                self.go(target)
            elif self.page == 'torch_light' and self.index == 0:
                self.torch_on = not self.torch_on
                self.noted = 'État de torche simulé : aucun matériel commandé.'
            else:
                self.go('undocumented', title=item['label'])
        elif self.page == 'fm_radio':
            self.noted = 'Tuner FM simulé — aucune commande matérielle.'
        elif self.page == 'file_empty':
            self.noted = 'Création de fichier non implémentée.'

    def left_softkey(self):
        sc = self.screen()
        if self.page == 'calculator':
            self.calculator_value = '0'
        elif self.page == 'torch_light':
            self.torch_on = not self.torch_on
            self.noted = 'Torche simulée — aucun accès LED.'
        elif sc and sc.get('left_target'):
            self.go(sc['left_target'])
        elif self.page == 'file_empty':
            self.noted = 'Nouvel élément non implémenté.'
        elif sc and sc['softkeys'][0] == 'Options':
            self.go('undocumented', title=f"{sc['title']} — Options")
        else:
            self.enter()

    def press_digit(self, digit):
        if self.page == 'calculator':
            self.calculator_value = str(digit) if self.calculator_value == '0' else (self.calculator_value + str(digit))[-10:]
            return
        if self.page == 'home':
            if 1 <= digit <= 9: self.index = digit - 1
            return
        n = len(self.items())
        if 1 <= digit <= n:
            self.index = digit - 1
            self.enter()

    def tune(self, step):
        if self.page == 'fm_radio' and self.earphones:
            self.frequency = round(min(108., max(87.5, self.frequency + step)), 1)
            self.noted = 'Fréquence graphique simulée, sans réception FM.'


class PhoneUIV5(v4.PhoneUI):
    """Reuses only the drawn chassis/icon primitives from V4. UI data is V5 JSON."""
    def __init__(self, registry, ui, rom, overlay):
        self.manifest, self.rom_doc, self.overlay_doc = ui, rom, overlay
        super().__init__(registry)
        self.model = UiModelV5(ui, overlay)
        self.root.title('F2 Virtual Menu Lab V5 — interface réelle / ROM prouvée')
        self.root.minsize(820, 710)
        self.paint()

    def home(self):
        self.gradient(0,300,'#0a8ceb','#0327b3')
        self.rect(0,0,240,40,'#0e92ed')
        grid = sorted(self.manifest['home_grid'],key=lambda item:item['slot'])
        self.txt(120,20,grid[self.model.index]['label'],16,v4.WHITE)
        for i,item in enumerate(grid):
            x = 47 + (i % 3)*73
            y = 82 + (i // 3)*66
            self.icon(item['icon'],x,y,i == self.model.index)
        self.rect(0,261,240,300,'#1978e4')
        self.line((0,261,240,261),fill='#8fc7ff')
        self.txt(6,280,'OK',15,v4.WHITE,anchor='w')
        self.txt(234,280,'Back',15,v4.WHITE,anchor='e')
        ox,oy = self.ax(0),self.ay(0)
        self.hotkey(ox,oy+261*1.21,ox+120*1.21,oy+300*1.21,self.model.left_softkey)
        self.hotkey(ox+120*1.21,oy+261*1.21,ox+240*1.21,oy+300*1.21,self.model.back)
        for i in range(9):
            x = ox + (10+(i%3)*73)*1.21
            y = oy + (49+(i//3)*66)*1.21
            def select(j=i):
                self.model.index=j
                self.model.enter()
            self.hotkey(x,y,x+67*1.21,y+61*1.21,select)

    def list_page(self, title, items, left='OK'):
        self.gradient(0,300,'#d0e1fc','#e8f1ff')
        self.heading(title)
        n=len(items)
        visible=min(7,n)
        row_h=min(35,max(27,219//max(1,visible)))
        start=max(0,min(self.model.index-6,n-7)) if n>7 else 0
        page=self.model.page
        for i in range(start,min(start+7,n)):
            item=items[i];y=41+(i-start)*row_h
            if i==self.model.index:
                self.rect(2,y,237,y+row_h-1,'#1775ed')
                self.rect(4,y+1,235,y+3,'#53a4ff')
            if page == 'file_manager':
                sym = '▣' if i==0 else '▤'
                self.txt(18,y+row_h//2,sym,17,'#4279d3')
                x=35
            elif page=='profiles':
                if item['label']=='Silent': self.txt(16,y+row_h//2,'✓',17,'#215ac2')
                x=36
            elif page=='storage_folders':
                self.txt(18,y+row_h//2,'▱',19,'#2a6fc9')
                x=35
            elif page == 'torch_light':
                self.rect(8,y+3,32,y+row_h-3,'#ddeaff' if i==self.model.index else '#d8e9ff',outline='#4c86dd')
                self.txt(20,y+row_h//2,str(i+1),14,'#436dc4',bold=False)
                x=37
            else:
                self.rect(8,y+3,32,y+row_h-3,'#ddeaff' if i==self.model.index else '#d8e9ff',outline='#4c86dd')
                self.txt(20,y+row_h//2,str(i+1),14,'#436dc4',bold=False)
                x=37
            self.txt(x,y+row_h//2,item['label'],14,fill='#152351',anchor='w')
            if page=='torch_light' and i==1:
                self.rect(180,y+3,233,y+row_h-3,'#2066d3')
                self.txt(206,y+row_h//2,'On' if self.model.torch_on else 'Off',13,'#eff7ff')
        self.footer(left,'Back')

    def camera(self):
        self.rect(0,0,240,300,'#111d37')
        self.rect(0,52,240,263,'#324d76')
        self.gradient(52,263,'#2c486f','#101d34')
        for x,txt in ((161,'+'),(188,'▲'),(217,'−')):
            self.rect(x,5,x+22,27,'#bfe0fd')
            self.txt(x+11,16,txt,12,'#2e5a98')
        self.footer('Options','Back')

    def phonebook(self):
        self.list_page('Phonebook',self.model.items(),'Options')
        self.rect(3,224,237,260,'#c7dbf7',outline='#7d9fcf')
        self.txt(12,240,'⌕',19,'#4a78be',anchor='w')
        self.txt(229,240,'✎abc',13,'#386bad',anchor='e')

    def calculator(self):
        self.gradient(0,300,'#bed2f3','#e5efff')
        self.rect(0,0,240,78,'#d8e6fb',outline='#94aaca')
        self.txt(227,63,self.model.calculator_value,17,'#2b3b64',anchor='e')
        self.rect(98,99,141,229,'#d8e7fc',outline='#7d9ecb')
        self.rect(55,145,184,184,'#d8e7fc',outline='#7d9ecb')
        for x,y,t in ((119,109,'+'),(76,165,'×'),(164,165,'÷'),(119,213,'−')):
            self.txt(x,y,t,22,'#476ca9')
        self.oval(100,145,140,185,'#1161d3')
        self.txt(120,166,'=',23,'#ffffff')
        self.footer('Clear','Back')

    def calendar_page(self):
        self.gradient(0,300,'#c7dcfa','#e9f2ff')
        self.heading('10/2026')
        self.rect(0,40,240,69,'#1973dc')
        self.txt(120,54,'08/10/2026',15,'#ffffff')
        weekdays=['M','T','W','T','F','S','S']
        for i,x in enumerate(weekdays):self.txt(24+32*i,83,x,12,'#3b5b95')
        dates=calendar.Calendar(firstweekday=0).monthdatescalendar(2026,10)
        for row,week in enumerate(dates[:6]):
            for col,day in enumerate(week):
                x=24+col*32;y=109+row*24
                is_today=day.month==10 and day.day==8
                if is_today:self.rect(x-14,y-11,x+14,y+11,'#1872db')
                self.txt(x,y,str(day.day),12,'#ffffff' if is_today else ('#adc0df' if day.month!=10 else '#273f70'))
        self.footer('Options','Back')

    def render_page(self):
        m=self.model
        if not isinstance(m,UiModelV5):
            return super().render_page()
        if m.page=='home':return self.home()
        if m.page=='audio_player':
            return self.simple_message('Audio Player','Virtual 0x8928\nNo native playback','Options')
        if m.page=='undocumented':
            return self.simple_message(m.subtitle or 'Not documented','Screen not observed')
        sc=m.screen()
        if sc is None:
            return self.simple_message(m.page,'Content not photographed')
        kind=sc['kind']
        if kind in ('numbered_list','storage_list','folder_list','profile_list','torch_list'):
            left=sc['softkeys'][0]
            if m.page=='torch_light':left='Off' if m.torch_on else 'On'
            return self.list_page(sc['title'],m.items(),left)
        if kind=='phonebook':return self.phonebook()
        if kind=='message':return self.simple_message(sc['title'],sc['message'],sc['softkeys'][0])
        if kind=='fm_radio':return self.fm()
        if kind=='camera_preview':return self.camera()
        if kind=='calendar':return self.calendar_page()
        if kind=='calculator':return self.calculator()
        return self.simple_message(sc['title'],'Not yet photographed')

    def keyboard(self, event):
        sym=event.keysym
        if sym in ('Up','Down','Left','Right'):
            if self.model.page == 'fm_radio' and self.model.earphones and sym in ('Left','Right'):
                self.model.tune(-0.1 if sym=='Left' else 0.1)
            else:
                delta = {'Up':-3,'Down':3,'Left':-1,'Right':1}[sym] if self.model.page=='home' else (-1 if sym in ('Up','Left') else 1)
                self.model.move(delta)
        elif sym in ('Return','KP_Enter'):
            self.model.enter()
        elif sym in ('Escape','BackSpace','F2'):
            self.model.back()
        elif sym == 'F1':
            self.model.left_softkey()
        elif sym.isdigit() and len(sym)==1:
            self.model.press_digit(int(sym))
        else:
            return
        self.paint()

    def evidence(self):
        if not isinstance(self.model,UiModelV5):
            return super().evidence()
        m=self.model
        sc=m.screen()
        lines=['F2 V5 — OBSERVED UI / ROM CONTRACT','',f'PAGE : {m.page}',
               f'MODE : {"Research Overlay (Audio virtuel)" if m.virtual_audio else "Real UI (photos)"}',
               '', 'EVIDENCE / SOURCE :']
        if sc:
            lines+=['  '+x for x in sc.get('evidence',[])]
            if sc.get('provenance_warning'):lines+=['',sc['provenance_warning']]
            if sc.get('note'):lines+=['',sc['note']]
        elif m.page=='home':
            row=self.manifest['home_grid'][m.index]
            lines+=row['evidence']
            lines.append(f'SLOT {m.index} : {row["label"]}')
        elif m.page=='audio_player':
            lines+=['Rom ID: 0x8928 (DUMP PROVEN)', 'UI visible on phone: NO', 'Callback: 0x1033D841', 'Entry stub: 0x1033D840', 'Init: 0x1033E815 -> 0x1033F83C', 'ROM child arrays do NOT enumerate 0x8928']
        else:
            lines.append('Contenu non documenté, écran volontairement neutre.')
        binding=ui_rom_binding(self.rom_doc,m.page)
        if binding:
            lines+=['','ROM LINK : '+json.dumps(binding,ensure_ascii=False)]
        if m.page=='multimedia':
            lines+=['','B702.children ROM = [0x8569,0x87ED]',
                    'FM Radio ROM ID = UNKNOWN (ne pas assigner 0x8569)',
                    '0x8928 absent de la liste originale B702.',
                    'Lien libellé Multimedia ↔ B702 non formellement résolu.']
        if m.page=='fm_radio':
            lines+=['',f'Jack simulé : {m.earphones}',f'98.7 = fréquence initiale de la photo, affichage courant: {m.frequency:.1f}']
        if m.noted:lines+=['',m.noted]
        lines+=['','NO USB / COM / FLASH / PHONE / NATIVE APP.','Manifest JSON editable; no pictures of private rooms shipped.']
        self.details.delete('1.0','end')
        self.details.insert('1.0','\n'.join(lines))


def main(argv=None):
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--firmware',type=Path)
    ap.add_argument('--verify',action='store_true',help='Check V5 manifest and canonical ROM, no GUI')
    ap.add_argument('--validate-json',action='store_true',help='Only check JSON manifest, no ROM required')
    args=ap.parse_args(argv)
    ui,rom,overlay=load_contract()
    if args.validate_json:
        print('V5.1 3-LAYER CONTRACT PASS — 9 slots, 2 observed Multimedia entries, unknown FM ID, Audio opt-in')
        return 0
    if not args.firmware:
        ap.error('--firmware required unless --validate-json')
    registry=Registry(args.firmware)
    stats=validate_against_registry(registry,rom)
    if args.verify:
        print('V5 ROM PASS — '+json.dumps(stats,ensure_ascii=False,sort_keys=True))
        return 0
    PhoneUIV5(registry,ui,rom,overlay).root.mainloop()
    return 0


if __name__=='__main__':sys.exit(main())
