@echo off
:: Установка кодировки UTF-8 для корректного отображения символов
chcp 65001 >nul

:: Переход в папку проекта
set "project_dir=C:\Pyth\WOT_auto"

if not exist "%project_dir%" (
    echo Error: Project directory "%project_dir%" does not exist.
    pause
    exit /b 1
)

cd /d "%project_dir%"

:: Проверка наличия Git
where git >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Git is not found. Make sure Git is installed and added to PATH.
    pause
    exit /b 1
)

:: Настройка поддельных данных для Git
echo Configuring fake Git identity...
git config user.name "Anonimus"
git config user.email "NotUrBusiness@yandex.ru"

:: Генерация даты и времени для сообщения коммита
for /f "tokens=2 delims==" %%i in ('"wmic os get localdatetime /value | findstr LocalDateTime"') do set datetime=%%i
set datestamp=%datetime:~0,8%
set timestamp=%datetime:~8,6%
set datetime_prefix=Update %datestamp%_%timestamp:~0,2%:%timestamp:~2,2%:%timestamp:~4,2%

:: Запрос у пользователя дополнительного текста для коммита
set /p commit_text=Enter commit message (optional): 
if "%commit_text%"=="" (
    set commit_message=%datetime_prefix%
) else (
    set commit_message=%datetime_prefix%: %commit_text%
)

:: Добавление всех изменений
echo Adding all changes to the repository...
git add .

:: Создание коммита
echo Creating a new commit with message: "%commit_message%"
git commit -m "%commit_message%"

:: Проверка наличия ветки main
echo Checking if branch 'main' exists...
git show-ref --verify --quiet refs/heads/main
if %ERRORLEVEL% neq 0 (
    echo Branch 'main' does not exist. Creating it...
    git checkout -b main
)

:: Проверка наличия облачного репозитория
echo Checking for cloud repository...
git remote show origin >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Cloud repository not found. Adding https://github.com/OnotoleChel/WOTAuto as 'origin'...
    git remote add origin https://github.com/OnotoleChel/WOTAuto.git
)

:: Получение последних изменений из