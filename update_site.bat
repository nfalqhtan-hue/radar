@echo off
rem Full cycle: run the agent, then push the new site/data.json to GitHub so the site updates.
rem Run hourly from Task Scheduler (task "Radar hourly update"). Output goes to update_site.log.
cd /d "%~dp0"
echo ===== %date% %time% =====
if defined TELEGRAM_TOKEN (echo telegram: on) else (echo telegram: off)
rem Start Ollama as its own hidden process if it is not running.
rem (Starting it inside this console kept the task "running" forever and blocked the next cycles.)
tasklist /FI "IMAGENAME eq ollama.exe" | find /I "ollama.exe" >nul || (powershell -NoProfile -Command "Start-Process ollama -ArgumentList serve -WindowStyle Hidden" & ping -n 9 127.0.0.1 >nul)
python radar_pipeline.py
git add site/data.json site/details.json site/events.json
git diff --cached --quiet || git commit -m "Update site data %date% %time%" --quiet
rem Push every cycle, so a push that failed earlier (e.g. no internet after startup) is retried.
git push --quiet && (echo pushed) || (echo push failed - will retry next cycle)
