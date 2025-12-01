"""
BetaCode - Sistema de Logging Estruturado

Este módulo fornece logging estruturado para todo o BetaCode,
com suporte para JSON logging, níveis de log e contexto.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import logging
import sys
import json
from datetime import datetime
from typing import Any, Dict, Optional
from pathlib import Path


class StructuredFormatter(logging.Formatter):
    """
    Formatter que produz logs estruturados em JSON.
    """

    def format(self, record: logging.LogRecord) -> str:
        """Formata log record como JSON"""
        log_data = {
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }

        # Adicionar contexto extra se existir
        if hasattr(record, 'context'):
            log_data['context'] = record.context

        # Adicionar informações de exceção se existir
        if record.exc_info:
            log_data['exception'] = self.formatException(record.exc_info)

        return json.dumps(log_data, ensure_ascii=False)


class ColoredConsoleFormatter(logging.Formatter):
    """
    Formatter que adiciona cores para console.
    """

    COLORS = {
        'DEBUG': '\033[36m',     # Ciano
        'INFO': '\033[32m',      # Verde
        'WARNING': '\033[33m',   # Amarelo
        'ERROR': '\033[31m',     # Vermelho
        'CRITICAL': '\033[35m'   # Magenta
    }
    RESET = '\033[0m'

    def format(self, record: logging.LogRecord) -> str:
        """Formata log com cores"""
        color = self.COLORS.get(record.levelname, self.RESET)
        record.levelname = f"{color}{record.levelname}{self.RESET}"
        return super().format(record)


class BetaCodeLogger:
    """
    Logger principal do BetaCode com suporte para logging estruturado.
    """

    _loggers: Dict[str, logging.Logger] = {}
    _log_file: Optional[Path] = None
    _log_level: int = logging.INFO
    _json_logging: bool = False

    @classmethod
    def setup(
        cls,
        log_file: Optional[str] = None,
        log_level: str = "INFO",
        json_logging: bool = False,
        console_output: bool = True
    ) -> None:
        """
        Configura o sistema de logging do BetaCode.

        Args:
            log_file: Caminho para arquivo de log (opcional)
            log_level: Nível de log (DEBUG, INFO, WARNING, ERROR, CRITICAL)
            json_logging: Se True, usa formato JSON estruturado
            console_output: Se True, envia logs para console
        """
        cls._log_level = getattr(logging, log_level.upper(), logging.INFO)
        cls._json_logging = json_logging

        if log_file:
            cls._log_file = Path(log_file)
            cls._log_file.parent.mkdir(parents=True, exist_ok=True)

    @classmethod
    def get_logger(cls, name: str) -> logging.Logger:
        """
        Retorna um logger configurado.

        Args:
            name: Nome do logger (geralmente __name__ do módulo)

        Returns:
            Logger configurado
        """
        if name in cls._loggers:
            return cls._loggers[name]

        logger = logging.getLogger(name)
        logger.setLevel(cls._log_level)
        logger.handlers.clear()  # Limpar handlers existentes

        # Handler para console
        console_handler = logging.StreamHandler(sys.stdout)
        console_handler.setLevel(cls._log_level)

        if cls._json_logging:
            console_handler.setFormatter(StructuredFormatter())
        else:
            console_formatter = ColoredConsoleFormatter(
                '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
                datefmt='%Y-%m-%d %H:%M:%S'
            )
            console_handler.setFormatter(console_formatter)

        logger.addHandler(console_handler)

        # Handler para arquivo se configurado
        if cls._log_file:
            file_handler = logging.FileHandler(cls._log_file, encoding='utf-8')
            file_handler.setLevel(cls._log_level)

            if cls._json_logging:
                file_handler.setFormatter(StructuredFormatter())
            else:
                file_formatter = logging.Formatter(
                    '%(asctime)s | %(levelname)s | %(name)s | %(message)s',
                    datefmt='%Y-%m-%d %H:%M:%S'
                )
                file_handler.setFormatter(file_formatter)

            logger.addHandler(file_handler)

        cls._loggers[name] = logger
        return logger


def get_logger(name: str) -> logging.Logger:
    """
    Atalho para obter logger configurado.

    Args:
        name: Nome do logger (use __name__ do módulo)

    Returns:
        Logger configurado

    Example:
        >>> from betacode.utils.logger import get_logger
        >>> logger = get_logger(__name__)
        >>> logger.info("Mensagem de log")
    """
    return BetaCodeLogger.get_logger(name)


def log_execution_time(func):
    """
    Decorator para logar tempo de execução de funções.

    Usage:
        @log_execution_time
        def my_function():
            # código
            pass
    """
    import time
    from functools import wraps

    @wraps(func)
    def wrapper(*args, **kwargs):
        logger = get_logger(func.__module__)
        start_time = time.time()

        try:
            result = func(*args, **kwargs)
            duration = time.time() - start_time
            logger.debug(
                f"Função {func.__name__} executada em {duration:.3f}s"
            )
            return result
        except Exception as e:
            duration = time.time() - start_time
            logger.error(
                f"Função {func.__name__} falhou após {duration:.3f}s: {e}"
            )
            raise

    return wrapper


class LogContext:
    """
    Context manager para adicionar contexto aos logs.

    Usage:
        with LogContext(logger, file="example.py", line=42):
            logger.info("Analyzing file")
    """

    def __init__(self, logger: logging.Logger, **context: Any):
        self.logger = logger
        self.context = context
        self.old_factory = None

    def __enter__(self):
        old_factory = logging.getLogRecordFactory()

        def record_factory(*args, **kwargs):
            record = old_factory(*args, **kwargs)
            record.context = self.context
            return record

        logging.setLogRecordFactory(record_factory)
        self.old_factory = old_factory
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.old_factory:
            logging.setLogRecordFactory(self.old_factory)


# Configuração padrão
BetaCodeLogger.setup(
    log_level="INFO",
    json_logging=False,
    console_output=True
)
