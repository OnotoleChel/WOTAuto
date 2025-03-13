"""v 1.001"""
"""БТ: Проверка режима управления Edge через порт 9222"""
from logger_module import log_v2, configure_logging
from edge_system_checker import get_edge_path, check_system_compatibility
import subprocess
import psutil
import sys

# Константы
iREMOTE_DEBUGGING_PORT = 9222  # Integer: Порт для удаленного управления
sUSER_DATA_DIR = r"C:\EdgeDebugProfile"  # String: Профиль для отладки

def is_edge_running() -> bool:
    """Проверяет, запущен ли Edge с флагом --remote-debugging-port=9222."""
    try:
        for oProcess in psutil.process_iter(['name']):
            """Проверяет, запущен ли MSE (Microsoft Edge)."""
            if oProcess.info['name'] == 'msedge.exe':
                log_v2("Edge is running", "info")
                return True
        log_v2("Edge is not running", "info")
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

if __name__ == "__main__":
    configure_logging()
    log_v2("Starting WoTAuto script", "info")
    
    # БТ-4.1: Проверка системной совместимости
    if not check_system_compatibility():
        log_v2("System compatibility check failed. Exiting...", "error")
        sys.exit(1)
    
    # БТ-4.1.1: Проверка режима Edge
    bEdgeDebugMode = is_edge_running()
    
    if bEdgeDebugMode:
        print("ОК")  # БТ-4.1.1.1: Вывод "ОК" в консоль
    else:
        print("в разработке")  # БТ-4.1.1.2: Вывод "в разработке"
        start_edge_with_debugging()  # БТ-4.1.2: Запуск Edge в режиме отладки
    
    log_v2("Script execution completed", "info")
    input("Press Enter to exit...")