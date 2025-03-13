from logger_module import log_v2, configure_logging
import sys
import os
import subprocess
import pefile

iTIMEOUT = 10

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

if __name__ == "__main__":
    iCode = 0
    try:
        configure_logging()
        
        # Получаем архитектуру драйвера
        sArch = get_driver_architecture()
        
        # Проверяем результат
        if sArch and sArch in ["x64", "x86", "ARM64"]:
            log_v2(f"Проверка успешно пройдена, архитектура {sArch}", "info")
        else:
            log_v2("Проверка завершена с ошибками", "error")
            iCode = 1
    except Exception as e:
        log_v2(f"Критическая ошибка: {str(e)}", "error")
        iCode = 2
    
    input("Нажмите Enter для завершения...")
    sys.exit(iCode)