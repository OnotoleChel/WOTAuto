"""v 1.001"""
"""БТ: Проверка режима управления Edge через порт 9222"""
from logger_module import log_v2, configure_logging
from edge_system_checker import get_edge_path, check_system_compatibility
import subprocess
import psutil
import sys
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.edge.service import Service
import time

# Константы
iREMOTE_DEBUGGING_PORT = 9222  # Integer: Порт для удаленного управления
sUSER_DATA_DIR = r"C:\EdgeDebugProfile"  # String: Профиль для отладки
TARGET_URL = "https://tanki.su/ru/daily-check-in/?utm_source=global-nav&utm_medium=link&utm_campaign=wot-portal"

def is_edge_running() -> bool:
    """Проверяет, запущен ли Edge с флагом --remote-debugging-port=9222."""
    try:
        for oProcess in psutil.process_iter(['name', 'cmdline']):
            if oProcess.info['name'] == 'msedge.exe' and '--remote-debugging-port=9222' in oProcess.info['cmdline']:
                log_v2("Edge is running in debugging mode", "info")
                return True
        log_v2("Edge is not running in debugging mode", "info")
    except Exception as e:
        log_v2(f"Error checking Edge status: {str(e)}", "error")
    return False

def start_edge_with_debugging() -> None:
    """Запускает Edge в режиме отладки через порт 9222."""
    try:
        sEdgePath = get_edge_path()
        sCommand = f'"{sEdgePath}" --remote-debugging-port={iREMOTE_DEBUGGING_PORT} --user-data-dir={sUSER_DATA_DIR}'
        log_v2(f"Starting Edge with command: {sCommand}", "info")
        subprocess.Popen(sCommand, shell=True)
        log_v2(f"Edge started in debugging mode on port {iREMOTE_DEBUGGING_PORT}", "info")
    except Exception as e:
        log_v2(f"Failed to start Edge: {str(e)}", "error")
        sys.exit(1)

def connect_to_edge_with_selenium():
    """Подключается к Edge через Selenium в режиме отладки."""
    try:
        # Настройка опций для подключения к уже запущенному Edge
        edge_options = Options()
        edge_options.add_experimental_option("debuggerAddress", f"127.0.0.1:{iREMOTE_DEBUGGING_PORT}")
        
        # Создание WebDriver
        driver = webdriver.Edge(options=edge_options)
        log_v2("Successfully connected to Edge via Selenium", "info")
        return driver
    except Exception as e:
        log_v2(f"Failed to connect to Edge via Selenium: {str(e)}", "error")
        sys.exit(1)

if __name__ == "__main__":
    configure_logging()
    log_v2("Starting WoTAuto script", "info")
    
    # БТ-4.1: Проверка системной совместимости
    if not check_system_compatibility():
        log_v2("System compatibility check failed. Exiting...", "error")
        sys.exit(1)
    
    # БТ-4.1.1: Проверка режима Edge
    bEdgeDebugMode = is_edge_running()
    
    if not bEdgeDebugMode:
        print("в разработке")  # БТ-4.1.1.2: Вывод "в разработке"
        start_edge_with_debugging()  # БТ-4.1.2: Запуск Edge в режиме отладки
        time.sleep(5)  # Ждем, пока Edge запустится
    
    # Подключение к Edge через Selenium
    driver = connect_to_edge_with_selenium()
    
    # Переход на целевой URL
    try:
        log_v2(f"Navigating to URL: {TARGET_URL}", "info")
        driver.get(TARGET_URL)
        log_v2("Successfully navigated to the target URL", "info")
    except Exception as e:
        log_v2(f"Failed to navigate to URL: {str(e)}", "error")
    
    # Ожидание завершения работы
    input("Press Enter to exit...")
    driver.quit()
    log_v2("Script execution completed", "info")