@echo off
chcp 65001 >nul
cd /d "%~dp0"
echo Radar: testing Ollama summaries on 20 real items...
python ollama_quality_test.py || py -3 ollama_quality_test.py
echo.
echo Finished. You can close this window.
pause
