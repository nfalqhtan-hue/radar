@echo off
rem Full cycle: run the agent, then push the new site/data.json to GitHub so the site updates.
rem Run hourly from Task Scheduler (task "Radar hourly update"). Output goes to update_site.log.
cd /d "%~dp0"
echo ===== %date% %time% =====
if defined TELEGRAM_TOKEN (echo telegram: on) else (echo telegram: off)
rem Start Ollama if it is not running (needed for Arabic summaries)
tasklist /FI "IMAGENAME eq ollama.exe" | find /I "ollama.exe" >nul || (start "" /B ollama serve >nul 2>&1 & ping -n 9 127.0.0.1 >nul)
python radar_pipeline.py
git add site/data.json
git diff --cached --quiet && (echo No new data & exit /b 0)
git commit -m "Update site data %date% %time%" --quiet
git push --quiet
echo pushed
