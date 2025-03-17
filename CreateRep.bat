@echo off
:: Переход в папку проекта
cd /d C:\Pyth\WOT_auto

:: Проверка наличия Git
where git >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo Git is not found. Make sure Git is installed and added to PATH.
    pause
    exit /b 1
)

:: Создание .gitignore файла
echo Creating .gitignore file...
(
    echo *.lnk
    echo *.txt
    echo *.bat
) > .gitignore

:: Инициализация локального репозитория
echo Initializing local Git repository...
git init

:: Добавление всех файлов в репозиторий
echo Adding files to the repository...
git add .

:: Первый коммит
echo Creating the first commit...
git commit -m "Initial commit"

:: Проверка статуса репозитория
echo Checking repository status...
git status

echo Local Git repository has been successfully created!
pause