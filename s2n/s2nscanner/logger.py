import logging
from logging.handlers import RotatingFileHandler
from rich.logging import RichHandler

LOGGER_NAME = "s2n"

def get_logger(name: str = None) -> logging.Logger:
    # name = "scanner" -> "s2n.scanner" 로거 이름 통일
    return logging.getLogger(f"{LOGGER_NAME}.{'.' + name if name else ''}")

def init_logger(verbose: bool=False, log_file: str=None) -> logging.Logger:
    # 중앙 로거 초기화 함수
    logger = get_logger()

    if logger.handlers:
        return logger
    
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # RichHandler for console output
    rh = RichHandler(rich_tracebacks=True, show_time=True, show_level=True)
    # Remove default formatter for RichHandler as it has its own
    logger.addHandler(rh)

    if log_file:
        fmt = logging.Formatter("[%(asctime)s] %(levelname)s in %(module)s: %(message)s")
        fh = RotatingFileHandler(log_file, maxBytes=10*1024*1024, backupCount=5)
        fh.setFormatter(fmt)
        logger.addHandler(fh)

    return get_logger()
