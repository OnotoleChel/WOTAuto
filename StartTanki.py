import os
import time
import psutil
import subprocess
from logger_module import log_v2, configure_logging

def start_and_monitor_tanki():
    """
    Запускает lgc.exe, затем Tanki.exe, и закрывает lgc.exe после загрузки Tanki.exe.
    """
    # Пути к исполняемым файлам
    lgc_path = r"C:\Games\Tanki\lgc_api.exe"  # Файл для запуска
    tanki_path = r"C:\Games\Tanki\Tanki.exe"

    # Команда для запуска lgc.exe с флагом --open
    lgc_command = f'"{lgc_path}" --open'

    try:
        # Запуск lgc.exe
        log_v2("Starting lgc.exe with command: --open")
        subprocess.Popen(lgc_command, shell=True)
        log_v2("lgc.exe started successfully.")

        # Ждём немного, чтобы процесс успел запуститься
        time.sleep(3)

        # Ожидание загрузки lgc.exe
        lgc_loaded = False
        while not lgc_loaded:
            for process in psutil.process_iter(['name']):
                try:
                    if process.name().lower() == 'lgc.exe':  # Используем правильное имя процесса
                        log_v2("lgc.exe is running.")
                        lgc_loaded = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Пропускаем процессы, к которым нет доступа
                    continue
            if not lgc_loaded:
                log_v2("Waiting for lgc.exe to load...")
                time.sleep(1)

        # Запуск Tanki.exe
        log_v2("Starting Tanki.exe")
        subprocess.Popen(f'"{tanki_path}"', shell=True)
        log_v2("Tanki.exe started successfully.")

        # Ожидание загрузки Tanki.exe
        tanki_loaded = False
        while not tanki_loaded:
            for process in psutil.process_iter(['name']):
                try:
                    if process.name().lower() == 'tanki.exe':
                        log_v2("Tanki.exe is running.")
                        tanki_loaded = True
                        break
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    # Пропускаем процессы, к которым нет доступа
                    continue
            if not tanki_loaded:
                log_v2("Waiting for Tanki.exe to load...")
                time.sleep(1)

        # Закрытие lgc.exe
        """log_v2("Closing lgc.exe")
        for process in psutil.process_iter(['name']):
            try:
                if process.name().lower() == 'lgc.exe':  # Используем правильное имя процесса
                    process.terminate()
                    log_v2("lgc.exe terminated successfully.")
                    break
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                # Пропускаем процессы, к которым нет доступа
                continue"""

    except Exception as e:
        log_v2(f"Error during start_and_monitor_tanki: {str(e)}", "error")

# Запуск процесса
if __name__ == "__main__":
    configure_logging()
    log_v2("Launch Tanki")
    start_and_monitor_tanki()
    log_v2("Complete")