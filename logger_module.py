"""v 0.100"""
import logging

# Настройка логирования
def configure_logging():
    """Настройка логирования."""
    logging.basicConfig(
        filename='WBA-0.txt',
        level=logging.DEBUG,
        format='%(asctime)s - %(levelname)s - %(message)s',
        encoding='utf-8'
    )

# Функция логирования
def log_v2(log_data, log_type="info"):
    """Логирование с выводом в консоль и файл."""
    print(log_data)  # Вывод в консоль
    if log_type == "info":
        logging.info(log_data)  # Запись в лог как INFO
    elif log_type == "error":
        logging.error(f"!ERROR! {log_data}")  # Запись в лог как ERROR
    else:
        logging.debug(f"?DEBUG? {log_data}")  # Запись в лог как DEBUG