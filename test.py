def is_edge_in_debug_mode() -> bool:
    """
    Проверяет, запущен ли MSE с флагом --remote-debugging-port=9222.
    Возвращает True, если Edge открыт в режиме отладки, иначе False.
    """
    bHaveEdge = False   #признак наличия запущёного Edge
    bHave9222 = False   #признак наличия 9222 Edge
    try:
        # Перебираем все процессы MSE
        for oProcess in psutil.process_iter(['name', 'cmdline']):
            if oProcess.info['name'] == 'msedge.exe':
                bHaveEdge = True
                # Проверяем аргументы командной строки
                sCmdline = " ".join(oProcess.info['cmdline'])
                if '--remote-debugging-port=9222' in sCmdline:
                    log_v2("Edge is running in remote debugging mode on port 9222", "info")
                    bHave9222 = True
                    break                    
                else:
                    log_v2("Edge is running without remote debugging mode", "info")
                    
        # Если Edge не запущен (но по условию он точно открыт)
        if !bHaveEdge:
            ("Unexpected: Edge is not running", "info")
            return (bHaveEdge && bHave9222)
    except Exception as e:
        log_v2(f"Error checking Edge debug mode: {str(e)}", "error")
        return False