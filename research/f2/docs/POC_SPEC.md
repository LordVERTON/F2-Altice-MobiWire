# Altice F2 — Audio Player POC Specification

Status: FROZEN AFTER S11
Target: canonical physical firmware dump only
Firmware: ALTICE_F2_DS_V02.1_181023_MP
Platform: MT6261

## 1. Canonical firmware

Physical dump:

research/f2/data/dumps/mobiwire_dump_2.bin

Size:
0x400000 bytes

SHA256:
2fc100e5704cf3d6fae0817a22ce222397702ffd7351a83763ae1bafd4416922

Validation dump:

research/f2/data/dumps/mobiwire_dump_3.bin

dump_2 and dump_3 are bit-identical.

No patch may be derived from dump_1.

---

## 2. Scope of first POC

Goal:

Trigger native MP3 playback from a fixed filename located in the
firmware-native audio directory.

Initial test filename:

test.mp3

Runtime path:

<drive>:\Audios\test.mp3

The drive letter MUST NOT be hardcoded.

No File Manager integration is required for the first playback POC.

No menu integration is required for the first playback POC.

No NVRAM write is required.

No audio routing override is allowed.

Native AudioDrain / PcmSink / AFE routing must remain untouched so
speaker/headset selection continues to be handled by the firmware.

---

## 3. Dynamic drive selection

Native getter:

0xF02B8FE8

Prototype used by the POC:

uint8_t get_audio_drive(void);

Confirmed behavior:

- no useful input arguments
- result returned in r0
- result ultimately used directly as the `%c` argument of native
  path formatting
- successful fallback values are ASCII drive letters such as
  'C', 'D', 'E', 'F'

Preference source:

0xF00AD89D

Native validation:

0xF0216E2C

Observed usage:

validate_drive(drive, 0)

Return value 0 is treated as valid.

Fallback wrapper:

0xF0229230

Actual fallback:

0xF0215C6C(8, 2, 0x18)

---

## 4. Native path convention

Native formatter:

0xF022DC34

Confirmed format string:

0xF02F44A4 = "%c:\\"

Native concatenation helper:

0xF02E2A08

Confirmed UTF-16 directory fragment:

L"Audios\\"

Native firmware repeatedly performs the equivalent of:

format(path, "%c:\\", drive);
concat(path, L"Audios\\");

Therefore the POC may use a static UTF-16 template:

WCHAR path[] = L"?:\\Audios\\test.mp3";

Then:

drive = get_audio_drive();

if (validate_drive(drive, 0) != 0)
    abort;

path[0] = (WCHAR)drive;

No SD-card drive letter is to be hardcoded.

---

## 5. Frontend extension classification

Extension classifier:

0xF02F4390

Extension table:

0xF0347DF8

Entries are UTF-16 strings of 5 WCHAR / 10 bytes.

Confirmed table:

0 = mp3
1 = amr
2 = aac
3 = wav
4 = mid
5 = midi
6 = imy
7 = terminator

For the first POC only MP3 is in scope.

Frontend recognition does NOT by itself prove playback support for
every listed extension.

---

## 6. Native filename splitting

Helper:

0xF02F7228

Functional ABI:

split_name_ext(src, stem, ext)

Observed behavior:

- copies source into stem
- searches UTF-16 '.'
- removes extension from stem when applicable
- copies characters after '.' into ext
- extension output length is limited to 5 WCHAR

This confirms native reconstruction of:

stem + L"." + extension

This frontend machinery is documented for later File Manager /
playlist integration and is NOT required by the fixed-file POC.

---

## 7. Audio player public object

Constructor:

0x10303BE0

Object size:

0x84 bytes

Public interface:

+0x00 Open     = 0x1028D230
+0x04 Close    = 0x1029D3BC
+0x08 Play     = 0x1028D394
+0x0C Stop     = 0x1028D4C0
+0x10 Pause    = 0x1028D378
+0x14 Resume   = 0x1028D41C
+0x18 Set      = 0x1028D43A
+0x1C Get      = 0x1028D114
+0x20 Destroy  = 0x1028D0D4

Constructor is treated as having no useful arguments for this POC.

---

## 8. Open configuration ABI

Minimal confirmed structure:

struct med_aud_player_cfg_altice {
    uint32_t unk00;       // +0x00
    WCHAR   *file_name;   // +0x04
    void    *data_p;      // +0x08
    uint32_t data_len;    // +0x0C
    uint8_t  format;      // +0x10
    uint8_t  pad[3];
    void    *cb_fct;      // +0x14
    void    *cb_param;    // +0x18
};

For file playback:

file_name = UTF-16 path
data_p    = NULL
data_len  = 0
cb_fct    = NULL
cb_param  = NULL

The callback may be NULL for the first playback POC.

Open copies cb_fct and cb_param into the player object.

The cfg structure itself therefore does not need to remain alive after
Open returns.

For safety, the UTF-16 filename buffer will remain static for the
entire playback session.

---

## 9. MP3 Open dispatch

Native media-type helper:

0xF02ADD64

MP3 suffix:

".MP3"

MP3 media type:

0x05

MP3 handler:

DAF_Open = 0x10358254

Confirmed Open MP3 call:

DAF_Open(
    cfg->cb_fct ? 0x1029D40C : NULL,
    &player->fsal,
    NULL
);

Therefore with cb_fct == NULL:

DAF_Open(
    NULL,
    &player->fsal,
    NULL
);

The embedded FSAL context is located at:

player + 0x2C

The player object must remain alive while playback is active.

---

## 10. Playback lifecycle

Minimum target sequence:

player = construct();

Open(player, &cfg);

Play(player);

Cleanup:

Stop(player);
Close(player);
Destroy(player);

Preferred cleanup order is strictly:

Stop -> Close -> Destroy

Close destroys the internal MHdl and closes the FSAL file context.

Destroy frees the public player wrapper.

Destroy alone must NOT be assumed to perform Close.

---

## 11. Internal MHdl methods

Confirmed internal map:

+0x0DC SetUserData
+0x0E0 GetUserData
+0x0F0 Play
+0x0F8 Stop
+0x0FC Pause
+0x100 Resume
+0x104 event translation
+0x108 Destroy

Public states observed:

0x00 = stopped / initial
0x1E = playing
0x20 = paused

---

## 12. Callback semantics

Internal callback wrapper:

0x1029D40C

Async handler:

0x102AAEE0

Logical user callback:

cb_fct(
    player,
    translated_event,
    cb_param
);

If cb_fct is NULL the async handler exits cleanly.

Therefore:

cfg.cb_fct   = NULL;
cfg.cb_param = NULL;

is valid for the first fixed-file playback POC.

---

## 13. Native audio routing

Confirmed native playback flow includes:

PcmSink_TerminateSound
KT_StopAndWait
TONE_StopAndWait
DPMGR_Load
parser Start
Media_SetAudioFormat
decoder Start
SetParameter(PcmSink)
AudioDrain_Start

Important:

The POC must NOT manually force speaker output.

Expected behavior:

- speaker when no headset is connected
- headset/jack when connected

This must remain under native firmware audio routing control.

---

## 14. Minimal logical POC

Pseudo-code only:

static WCHAR path[] =
    L"?:\\Audios\\test.mp3";

drive = get_audio_drive();

if (validate_drive(drive, 0) != 0)
    return ERROR_DRIVE;

path[0] = (WCHAR)drive;

player = aud_player_media_construct();

if (!player)
    return ERROR_PLAYER;

memset(&cfg, 0, sizeof(cfg));

cfg.file_name = path;
cfg.cb_fct    = NULL;
cfg.cb_param  = NULL;

ret = player->Open(player, &cfg);

if (ret != 0) {
    player->Destroy(player);
    return ERROR_OPEN;
}

player->Play(player);

/*
 * For the first trigger POC the exact public Play status mapping does
 * not need to be relied upon.
 *
 * Successful backend Play is known to use MHdl status 0xC8 and changes
 * player state to 0x1E.
 */

/* eventual controlled cleanup */

player->Stop(player);
player->Close(player);
player->Destroy(player);

---

## 15. Explicit non-goals for first patch

The first offline patch does NOT implement:

- Multimedia menu entry
- File Manager selector
- playlist UI
- Play/Pause UI
- Previous/Next
- persistent preferred storage
- NVRAM changes
- forced speaker routing
- forced headset routing
- generic multi-format playback

Those belong to later stages after fixed MP3 playback is proven.

---

## 16. Safety constraints

No phone write is authorized during the offline POC phase.

Before any future device write:

1. derive only from canonical dump_2
2. preserve dump_3 untouched
3. identify exact code cave
4. record original bytes
5. generate patched image reproducibly
6. compute original and patched hashes
7. produce exact binary diff
8. define rollback bytes
9. verify patched regions are outside:
   - NVRAM
   - IMEI
   - calibration
   - user filesystem
10. perform read-back after any future flash

Current phase remains:

OFFLINE / READ-ONLY
