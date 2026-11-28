@echo off
rem Daily X post at 13:00 (Task Scheduler task "Radar X daily"). Output goes to x_post_run.log; results also in x_post.log.
cd /d "%~dp0"
echo ===== %date% %time% =====
python x_post.py --post
