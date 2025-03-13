"""v 2.000"""
"""Настройки логирования вынесены в отдельный модуль"""
"""Убрано debug логирование"""
"""Добавлена функция получения архитектуры МSEdge"""
"""Добавлена функция получения архитектуры драйвера"""
"""Добавлена функция сверки архитектуры"""
from logger_module import log_v2, configure_logging
import subprocess
import sys
from shutil import which
import re
import pefile
import os

# Константы
sSEP = f"\n{'-'*30}\nNew execution started\n{'-'*30}"  # Разделитель для логов (строка)
iTIMEOUT = 10  # Таймаут для subprocess (целое число)

# Вызываем configure_logging() при загрузке модуля
configure_logging()

# Получение пути к Edge
def get_edge_path():
    """Получает путь к исполняемому файлу MSEdge."""
    sEdgePath = which("msedge.exe")
    if not sEdgePath:
        asPossiblePaths = [
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe"
        ]
        for sPath in asPossiblePaths:
            if which(sPath):
                sEdgePath = sPath
                break
    if not sEdgePath:
        raise FileNotFoundError("MSEdge executable not found")
    return sEdgePath

# Получение версии через WMIC
def get_version_via_wmic(file_path):
    """Получает версию исполняемого файла через WMIC."""
    try:
        sEscapedPath = file_path.replace("\\", "\\\\")
        sCommand = f'wmic datafile where "name=\'{sEscapedPath}\'" get Version /value'
        oResult = subprocess.run(
            sCommand,
            shell=True,
            capture_output=True,
            text=True,
            timeout=iTIMEOUT,
            check=True
        )
        sOutput = oResult.stdout.strip()
        match = re.search(r'Version=(\d+\.\d+\.\d+\.\d+)', sOutput)
        return match.group(1) if match else None
    except Exception as e:
        log_v2(f"Error getting version via wmic: {str(e)}", "error")
        return None

# Получение версии Edge
def get_edge_version():
    """Проверяет версию MSEdge."""
    sEdgePath = get_edge_path()
    
    sVersion = get_version_via_wmic(sEdgePath)
    if sVersion:
        log_v2(f"MSEdge version detected: {sVersion}", "info")
        return sVersion

    try:
        import winreg
        oKey = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\WOW6432Node\Microsoft\Edge\BLBeacon")
        sVersion, _ = winreg.QueryValueEx(oKey, "Version")
        winreg.CloseKey(oKey)
        log_v2(f"MSEdge version detected: {sVersion}", "info")
        return sVersion
    except Exception as e:
        log_v2(f"Registry error: {str(e)}", "error")

    try:
        oResult = subprocess.run(
            [sEdgePath, "--headless=new", "--product-version"],
            capture_output=True,
            text=True,
            timeout=iTIMEOUT,
            check=True
        )
        sVersion = oResult.stdout.strip()
        log_v2(f"MSEdge version detected: {sVersion}", "info")
        return sVersion
    except subprocess.CalledProcessError as e:
        log_v2(f"Error executing Edge: {str(e)}", "error")
        return None

# Получение версии драйвера
def get_driver_version():
    """Проверяет версию msedgedriver."""
    sDriverPath = which("msedgedriver.exe")
    if not sDriverPath:
        asPossiblePaths = [
            r"C:\Program Files\Microsoft\Edge\Application\msedgedriver.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedgedriver.exe"
        ]
        for sPath in asPossiblePaths:
            if which(sPath):
                sDriverPath = sPath
                break
    if not sDriverPath:
        log_v2("MSEdge driver not found", "error")
        return None
    
    sVersion = get_version_via_wmic(sDriverPath)
    if sVersion:
        log_v2(f"MSEdge driver version detected: {sVersion}", "info")
        return sVersion
    else:
        log_v2("Failed to get driver version", "error")
        return None

# Проверка Selenium
def check_selenium():
    """Проверяет наличие и версию Selenium."""
    try:
        import selenium
        log_v2(f"Selenium installed (version: {selenium.__version__})", "info")
        aiSeleniumVersion = tuple(map(int, selenium.__version__.split('.')[:2]))
        if aiSeleniumVersion < (4, 10):
            log_v2("Outdated Selenium version. Minimum required: 4.10.0", "error")
            return False
        return True
    except ImportError:
        log_v2("Selenium is not installed. Install via 'pip install selenium'", "error")
        return False

def get_edge_architecture():
    try:
        # Получаем путь к файлу Edge
        edge_path = get_edge_path()
        sArch = ""
        # Открываем файл через pefile
        pe = pefile.PE(edge_path)
        if pe.FILE_HEADER.Machine == 0x8664:
            sArch = "x64"
        elif pe.FILE_HEADER.Machine == 0x14C:
            sArch = "x86"
        elif pe.FILE_HEADER.Machine == 0xAA64:
            sArch = "ARM64"
        else:
            sArch = "Unknown architecture"
        log_v2(f"MSEdge architecture detected: {sArch}", "info")
        return sArch
    except Exception as e:
        sArch = str(e)
        log_v2(f"MSEdge architecture detection error: {sArch}", "info")
        return None
    
    
def get_driver_architecture():
    """Определяет архитектуру драйвера через PowerShell."""
    try:
        possible_paths = [
            r"C:\Program Files\Microsoft\Edge\Application\msedgedriver.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedgedriver.exe"
        ]
        sDriver_path = None
        for sPath in possible_paths:
            if os.path.exists(sPath):
                sDriver_path = sPath
                break
        
        # Если драйвер не найден
        if not sDriver_path:
            raise FileNotFoundError("MSEdge driver executable not found")
        
        # Используем pefile для анализа PE-заголовка
        pe = pefile.PE(sDriver_path)
        if pe.FILE_HEADER.Machine == 0x8664:
            arch = "x64"
        elif pe.FILE_HEADER.Machine == 0x14C:
            arch = "x86"
        elif pe.FILE_HEADER.Machine == 0xAA64:
            arch = "ARM64"
        else:
            arch = "Unknown architecture"
        
        log_v2(f"MSEdge driver architecture detected: {arch}", "info")
        return arch
    except Exception as e:
        log_v2(f"Error getting driver architecture: {str(e)}", "error")
        return None

# Основная проверка совместимости системы
def check_system_compatibility():
    """
    Выполняет полную проверку системы.
    Возвращает True, если система готова к работе, иначе False.
    """
    try:
        sEdgeVersion = get_edge_version()
        sDriverVersion = get_driver_version()
        bIsSeleniumReady = check_selenium()

        # Проверка архитектуры
        sEdgeArch = get_edge_architecture()
        sDriverArch = get_driver_architecture()
        
        if not sEdgeArch or not sDriverArch:
            log_v2("Failed to detect architectures of Edge or driver", "error")
            return False
        
        if sEdgeArch != sDriverArch:
            log_v2(f"Architecture mismatch! Edge: {sEdgeArch}, Driver: {sDriverArch}", "error")
            print("Download the correct driver from: https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/")
            return False

        # Проверка версий
        if sEdgeVersion and sDriverVersion and bIsSeleniumReady:
            asEdgeParts = sEdgeVersion.split(".")[:2]
            asDriverParts = sDriverVersion.split(".")[:2]
            
            if asEdgeParts == asDriverParts:
                log_v2("Edge and driver versions are compatible", "info")
                return True
            else:
                log_v2(f"Version mismatch! Edge: {sEdgeVersion} vs Driver: {sDriverVersion}", "error")
                print("Download the correct driver from: https://developer.microsoft.com/en-us/microsoft-edge/tools/webdriver/")
                return False
        else:
            log_v2("Failed to get both versions or Selenium is not ready", "error")
            return False
    except Exception as e:
        log_v2(f"Error during system compatibility check: {str(e)}", "error")
        return False      
        
if __name__ == "__main__":
    iCode = 0
    try:
        configure_logging()
        log_v2("Запуск проверки системной совместимости через CLI", "info")
        if check_system_compatibility():
            log_v2("Проверка успешно пройдена", "info")
        else:
            log_v2("Проверка завершена с ошибками", "error")
            iCode = 1
    except Exception as e:
        log_v2(f"Критическая ошибка: {str(e)}", "error")
        iCode = 2
    input("Нажмите Enter для завершения...")
    sys.exit(iCode)