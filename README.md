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
| Wert-Scan (Byte…Double), exakt/ungefähr/größer/kleiner/zwischen/unbekannt, erhöht/verringert (um X), geändert/unverändert | Hauptfenster |
| **Alle Zahlentypen auf einmal** (4/8 Bytes, Float, Double, Cent-Werte ×10/×100) – Typ muss nicht bekannt sein | Datentyp |
| **Rauschfilter**: 5 s „unverändert“ scannen, während du nichts tust (entfernt Timer, Positionen …) | Hauptfenster |
| **Scan-Hotkeys** im Spiel: Strg+Num+ / − / 0 / * / ÷ = erhöht / verringert / gleich / geändert / exakt (mit Ton) | Hauptfenster |
| **Live-Trefferliste**: grün = gestiegen, rot = gesunken | Hauptfenster |
| **Such-Assistent**: Schritt-für-Schritt-Tipps passend zum aktuellen Stand | Knopf „Assistent“ |
| **Unity-Explorer**: Werte per Name finden (z. B. `coins`) – IL2CPP und Mono, Objekte samt Live-Wert, entschlüsselt Anti-Cheat-Toolkit-Werte (🔓) | Knopf „Unity“ |
| **Werteverlauf**: Live-Graph mehrerer Adressen | Rechtsklick |
| **Struktur-Ansicht**: Werte rund um eine Adresse (int/float/Zeiger), Änderungen gelb, bei Unity mit Feldnamen | Rechtsklick |
| **Wer zeigt hierhin?**: Zeiger auf eine Adresse/ein Objekt, statische zuerst → stabile Zeigerkette | Rechtsklick |
| **Welche Adressen nutzt dieser Befehl?** (z. B. Leben von Spieler und Gegnern) | Rechtsklick |
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
   - Unity-Spiel (z. B. Vampire-Survivors-Engine)? → **Unity** → `coins` suchen → Doppelklick → Wert direkt da.
2. Wert eingeben → **Erster Scan** (Typ „Alle Zahlentypen“); Wert im Spiel ändern → **Nächster Scan**; wiederholen
   - Wird der Wert gerundet angezeigt? → „Ungefähr (gerundet)“. Unbekannt? → „Unbekannter Startwert“ + Rauschfilter.
3. Treffer doppelklicken → Adressliste
4. Rechtsklick → **Pointer-Scan**, damit der Cheat nach Neustart funktioniert
   (Spiel neu starten, Wert neu finden, **Rescan** mit neuer Adresse)
5. Alternativ Rechtsklick → **Was schreibt auf diese Adresse?** → Befehl durch NOPs ersetzen
6. Hotkeys setzen (Rechtsklick → Bearbeiten), dann **Datei → Trainer exportieren**

## Claude-Schnittstelle
`cli.py` bietet die wichtigsten Funktionen als Kommandozeile mit JSON-Ausgabe; `toolhub.json` beschreibt sie für
ToolHub, das sie Claude per MCP zur Verfügung stellt. Befehle: `processes`, `scan` (mehrstufig, Zustand in `%TEMP%\memtrainer`),
`noise`, `monitor`, `struct`, `refs`, `writes`/`trace` (Debugger, mit `--dry-run`), `unity-search`, `unity-objects`,
`read`, `write` (mit `--dry-run`), `aob`, `text`, `speed`, `table`.

```
python cli.py scan --process game.exe --value 336,7 --new          # alle Zahlentypen
python cli.py scan --process game.exe --mode "Verringert um" --value 100
python cli.py monitor --process game.exe --expr 7FF6A1B2C3D0 --type Float --seconds 5
python cli.py unity-search --process game.exe --query coins
python cli.py unity-objects --process game.exe --class PlayerOptionsData --field Coins
python cli.py write --process game.exe --expr 7FF6A1B2C3D0 --value 99999 --dry-run
```
Einfrieren, Hotkeys und Pointer-Scans bleiben der GUI bzw. dem exportierten Trainer vorbehalten.

## Grenzen
- Debugger: Spiele mit Anti-Debug-Schutz können abstürzen.
- Unity-Explorer: nur 64-bit; ruft Funktionen der Unity-Laufzeit im Spiel auf (eigener kurzer Thread). Mono ist
  umgesetzt, aber bisher nur mit IL2CPP-Spielen getestet.
- Speedhack wirkt über QueryPerformanceCounter/GetTickCount/timeGetTime – Spiele mit eigener Zeitmessung reagieren evtl. nicht.
- Patches/Speedhack gelten nur, solange das Spiel läuft (beim nächsten Start neu aktivieren – der Trainer macht das automatisch).

## Dateien
`memtrainer.py` (Hauptfenster) · `gui_tools.py`, `gui_extra.py` (Werkzeug-Fenster) · `scanner_core.py` (Speicherzugriff,
Scan) · `trainer_core.py` (Cheat-Einträge, Ausdrücke, Tabellen) · `pointer_scan.py` · `aob.py` · `debugger.py` ·
`speedhack.py` · `unity.py` + `remote.py` (Unity-Explorer) · `trainer_app.py` (exportierter Trainer) ·
`tests/` (`python -m unittest discover -s tests`)

> **Hinweis:** Nur für Singleplayer-/Offline-Spiele. In Online-Spielen mit Anti-Cheat droht ein Bann. Weil das Tool Speicher fremder Prozesse liest/schreibt, melden manche Virenscanner es fälschlich als „Hacktool“.

## Lizenz

MIT – siehe [LICENSE](LICENSE).
