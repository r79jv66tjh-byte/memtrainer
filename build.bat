@echo off
rem Baut dist\MemTrainer.exe (laeuft ohne installiertes Python).
cd /d "%~dp0"
python -m pip install --user --quiet numpy capstone pyinstaller
python -m PyInstaller --noconfirm --onefile --windowed --name MemTrainer ^
  --add-data "trainer_app.py;." --add-data "scanner_core.py;." --add-data "trainer_core.py;." ^
  --add-data "aob.py;." --add-data "speedhack.py;." --add-data "presets;presets" ^
  --collect-all capstone memtrainer.py
echo.
echo Fertig: dist\MemTrainer.exe
