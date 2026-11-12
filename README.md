# MemTrainer

Speicher-Scanner & Trainer-Baukasten für Singleplayer-Spiele unter Windows – Werte finden, einfrieren,
Pointer suchen, Code patchen, Spiel beschleunigen und daraus einen eigenen Trainer (.exe) bauen.

> Nur für Offline-/Singleplayer-Spiele. In Online-Spielen mit Anti-Cheat droht ein Bann.

## Start
- `start.bat` (installiert numpy bei Bedarf) oder `python memtrainer.py`
- Oder als Programm ohne Python: `build.bat` → `dist\MemTrainer.exe`

Benötigt 64-bit Python 3 + `numpy`; optional `capstone` (Disassembler) und `pyinstaller` (exe-Export).
Läuft das Spiel als Administrator, muss auch der Scanner als Administrator laufen.

## Funktionen
| Funktion | Wo |
|---|---|
| Wert-Scan (Byte…Double), exakt/größer/kleiner/zwischen/unbekannt, erhöht/verringert (um X), geändert/unverändert | Hauptfenster |
| Scan rückgängig (bis 5 Schritte) | „Rückgängig“ |
| Adressliste mit Gruppen, Einfrieren (halten / nicht weniger / nicht mehr), Hotkeys (Ein/Aus, Wert setzen, Wert addieren) | unten, Rechtsklick |
| Adress-Ausdrücke: `spiel.exe+1A2B`, `[[spiel.exe+10]+48]+8` | überall |
| Pointer-Scanner inkl. Rescan nach Neustart und Speichern der Ketten | Werkzeuge / Rechtsklick |
| „Was schreibt / greift auf diese Adresse zu?“ (Hardware-Breakpoint) → Befehl per NOP abschalten | Rechtsklick |
| Code-Patches mit AOB-Signatur (überstehen Spiel-Updates oft) | Adressliste |
| Byte-Muster-Suche (AOB, `??` als Platzhalter) und Textsuche (UTF-8/UTF-16) | Werkzeuge |
| Speicher-Viewer mit Hex, Werte-Vorschau, Disassembler, Bytes schreiben | Werkzeuge |
| Speedhack 0,1x–10x (64-bit Spiele) | Werkzeuge |
| Tabellen speichern/laden (JSON) | Datei |
| **Trainer exportieren**: eigene .exe mit Checkboxen, Hotkeys, Speedhack-Hotkey, verbindet sich automatisch | Datei |

## Typischer Ablauf
1. Prozess wählen (Filter nach Name/Fenstertitel)
2. Wert eingeben → **Erster Scan**; Wert im Spiel ändern → **Nächster Scan**; wiederholen
3. Treffer doppelklicken → Adressliste
4. Rechtsklick → **Pointer-Scan**, damit der Cheat nach Neustart funktioniert
   (Spiel neu starten, Wert neu finden, **Rescan** mit neuer Adresse)
5. Alternativ Rechtsklick → **Was schreibt auf diese Adresse?** → Befehl durch NOPs ersetzen
6. Hotkeys setzen (Rechtsklick → Bearbeiten), dann **Datei → Trainer exportieren**

## Claude-Schnittstelle
`cli.py` bietet die wichtigsten Funktionen als Kommandozeile mit JSON-Ausgabe; `toolhub.json` beschreibt sie für
ToolHub, das sie Claude per MCP zur Verfügung stellt. Befehle: `processes`, `scan` (mehrstufig, Zustand in `%TEMP%\memtrainer`),
`read`, `write` (mit `--dry-run`), `aob`, `text`, `speed`, `table`.

```
python cli.py scan --process game.exe --type "4 Bytes" --value 1500 --new
python cli.py scan --process game.exe --mode "Verringert um" --value 100
python cli.py write --process game.exe --expr 7FF6A1B2C3D0 --value 99999 --dry-run
```
Einfrieren, Hotkeys und Pointer-Scans bleiben der GUI bzw. dem exportierten Trainer vorbehalten.

## Grenzen
- Debugger: Spiele mit Anti-Debug-Schutz können abstürzen.
- Speedhack wirkt über QueryPerformanceCounter/GetTickCount/timeGetTime – Spiele mit eigener Zeitmessung reagieren evtl. nicht.
- Patches/Speedhack gelten nur, solange das Spiel läuft (beim nächsten Start neu aktivieren – der Trainer macht das automatisch).

## Dateien
`memtrainer.py` (Hauptfenster) · `gui_tools.py` (Werkzeug-Fenster) · `scanner_core.py` (Speicherzugriff, Scan) ·
`trainer_core.py` (Cheat-Einträge, Ausdrücke, Tabellen) · `pointer_scan.py` · `aob.py` · `debugger.py` · `speedhack.py` ·
`trainer_app.py` (exportierter Trainer)

> **Hinweis:** Nur für Singleplayer-/Offline-Spiele. In Online-Spielen mit Anti-Cheat droht ein Bann. Weil das Tool Speicher fremder Prozesse liest/schreibt, melden manche Virenscanner es fälschlich als „Hacktool“.

## Lizenz

MIT – siehe [LICENSE](LICENSE).
