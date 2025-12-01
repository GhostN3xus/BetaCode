"""
BetaCode - Exceções Customizadas

Este módulo define todas as exceções específicas do BetaCode,
permitindo melhor tratamento de erros e debugging.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

from typing import Optional, Any


class BetaCodeException(Exception):
    """Exceção base para todas as exceções do BetaCode"""

    def __init__(self, message: str, details: Optional[Any] = None):
        self.message = message
        self.details = details
        super().__init__(self.message)

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} | Detalhes: {self.details}"
        return self.message


class ConfigurationError(BetaCodeException):
    """Erro relacionado a configuração inválida"""
    pass


class RuleLoadError(BetaCodeException):
    """Erro ao carregar regras"""
    pass


class RuleValidationError(BetaCodeException):
    """Erro de validação de regra"""
    pass


class FileReadError(BetaCodeException):
    """Erro ao ler arquivo"""
    pass


class FileWriteError(BetaCodeException):
    """Erro ao escrever arquivo"""
    pass


class AnalysisError(BetaCodeException):
    """Erro durante análise de código"""
    pass


class AnalysisTimeoutError(AnalysisError):
    """Timeout durante análise"""
    pass


class PatternCompilationError(BetaCodeException):
    """Erro ao compilar padrão regex"""
    pass


class ReportGenerationError(BetaCodeException):
    """Erro ao gerar relatório"""
    pass


class InvalidFormatError(BetaCodeException):
    """Formato de output inválido"""
    pass


class DependencyAnalysisError(BetaCodeException):
    """Erro durante análise de dependências"""
    pass


class IntegrationError(BetaCodeException):
    """Erro em integração externa"""
    pass


class APIError(BetaCodeException):
    """Erro na API"""
    pass


class AuthenticationError(BetaCodeException):
    """Erro de autenticação"""
    pass


class DatabaseError(BetaCodeException):
    """Erro de banco de dados"""
    pass


class ValidationError(BetaCodeException):
    """Erro de validação de dados"""
    pass


class UnsupportedLanguageError(BetaCodeException):
    """Linguagem não suportada"""
    pass


class LanguageDetectionError(BetaCodeException):
    """Erro ao detectar linguagem"""
    pass


def handle_exception(func):
    """
    Decorator para tratamento uniforme de exceções.

    Usage:
        @handle_exception
        def my_function():
            # código que pode lançar exceções
            pass
    """
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except BetaCodeException:
            # Re-raise exceções do BetaCode
            raise
        except FileNotFoundError as e:
            raise FileReadError(f"Arquivo não encontrado", details=str(e))
        except PermissionError as e:
            raise FileReadError(f"Permissão negada", details=str(e))
        except TimeoutError as e:
            raise AnalysisTimeoutError(f"Timeout excedido", details=str(e))
        except Exception as e:
            raise BetaCodeException(f"Erro inesperado em {func.__name__}", details=str(e))

    return wrapper
