@echo off
setlocal enabledelayedexpansion

:: Получаем текущую дату и время
for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value | findstr LocalDateTime"') do set datetime=%%i

:: Разбираем дату и время на части
set year=%datetime:~0,4%
set month=%datetime:~4,2%
set day=%datetime:~6,2%
set hour=%datetime:~8,2%
set minute=%datetime:~10,2%
set second=%datetime:~12,2%

:: Формируем сообщение коммита
set commit_msg=V_%year%.%month%.%day%_%hour%:%minute%:%second%

:: Выполняем Git команды
git add .
git commit -m "%commit_msg%"
git push

echo Commit and push completed with message: %commit_msg%
pause