"""v 1.500"""
"""БТ: Проверка режима управления Edge через порт 9222"""
"""БТ: Запуск сайта"""
"""БТ: Проверка логирования"""
"""БТ: Сбор дейлика"""
"""БТ: Запуск Tanki и lgc_api"""

# Импорты для основного скрипта
from logger_module import log_v2, configure_logging
from edge_system_checker import get_edge_path, check_system_compatibility
from StartTanki import start_and_monitor_tanki

import subprocess
import psutil
import sys
import time
import os
from selenium import webdriver
from selenium.webdriver.edge.options import Options
from selenium.webdriver.common.by import By
from selenium.common.exceptions import NoSuchElementException
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from selenium.webdriver.common.action_chains import ActionChains



# Константы
iREMOTE_DEBUGGING_PORT = 9222  # Порт для удаленного управления Edge
sUSER_DATA_DIR = r"C:\EdgeDebugProfile"  # Путь к пользовательскому профилю Edge для отладки
sTARGET_URL = "https://tanki.su/ru/daily-check-in/?utm_source=global-nav&utm_medium=link&utm_campaign=wot-portal"
# URL страницы с ежедневным бонусом

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
        edge_options = Options()
        edge_options.add_experimental_option("debuggerAddress", f"127.0.0.1:{iREMOTE_DEBUGGING_PORT}")
        driver = webdriver.Edge(options=edge_options)
        log_v2("Successfully connected to Edge via Selenium", "info")
        return driver
    except Exception as e:
        log_v2(f"Failed to connect to Edge via Selenium: {str(e)}", "error")
        sys.exit(1)

"""запуск Процесса"""
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
        log_v2(f"Navigating to URL: {sTARGET_URL}", "info")
        driver.get(sTARGET_URL)
        log_v2("Successfully navigated to the target URL", "info")
    except Exception as e:
        log_v2(f"Failed to navigate to URL: {str(e)}", "error")
        driver.quit()
        sys.exit(1)
    
    # Проверка наличия кнопки "Войти"
    try:
        login_button = driver.find_element(By.XPATH, '//span[@class="big-button_text" and text()="Войти"]')
        if login_button:
            print("Авторизуйтесь на сайте")
            log_v2("Login button found. Exiting script.", "info")
            driver.quit()
            sys.exit(0)
    except NoSuchElementException:
        log_v2("Log In complete", "info")
    
    # Проверка наличия элемента с подарком
    try:
        # Явное ожидание появления родительского элемента <div class="c_item c_default">
        gift_container = WebDriverWait(driver, 10).until(
            EC.element_to_be_clickable((By.XPATH, '//div[contains(@class, "c_item c_default")]'))
        )
        log_v2("Ready 2 get the daily gifts", "info")
        
        # Прокрутка элемента в зону видимости
        driver.execute_script("arguments[0].scrollIntoView(true);", gift_container)
        time.sleep(1)  # Даем время для завершения прокрутки
        
        # Попытка клика через JavaScript
        try:
            driver.execute_script("arguments[0].click();", gift_container)
            log_v2("The daily gift is got", "info")
        except Exception as e:
            log_v2(f"Failed to click on the gift container using JavaScript: {str(e)}", "error")
            
            # Попытка клика через ActionChains
            try:
                action = ActionChains(driver)
                action.move_to_element(gift_container).click().perform()
                log_v2("The daily gift is got using ActionChains", "info")
            except Exception as e:
                log_v2(f"Failed to click using ActionChains: {str(e)}", "error")
    except NoSuchElementException:
        # Если элемент не найден
        log_v2("No daily gifts", "info")
        driver.quit()
        sys.exit(0)
    ###запуск
    start_and_monitor_tanki    
    # Завершение работы с браузером
    driver.quit()
    log_v2("WoTAuto script finished successfully.", "info")
    
    # Запуск дополнительной функции
    start_and_monitor_tanki()