"""
BetaCode - Pattern Matcher

Este módulo fornece funcionalidade para matching de padrões
em código-fonte usando regex e outros métodos.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import re
from typing import List, Tuple, Optional, Pattern
from ..core.exceptions import PatternCompilationError
from ..utils.logger import get_logger

logger = get_logger(__name__)


class PatternMatcher:
    """
    Realiza matching de padrões em código-fonte.

    Suporta regex, case-insensitive matching e caching de patterns compilados.
    """

    def __init__(self):
        """Inicializa o pattern matcher com cache vazio"""
        self._pattern_cache: dict[str, Pattern] = {}

    def find_matches(
        self,
        pattern: str,
        code: str,
        rule_id: str,
        case_sensitive: bool = True,
        multiline: bool = True
    ) -> List[Tuple[int, int, str]]:
        """
        Encontra todas as ocorrências de um padrão no código.

        Args:
            pattern: Expressão regular para buscar
            code: Código-fonte para analisar
            rule_id: ID da regra (para logging)
            case_sensitive: Se o match deve ser case-sensitive
            multiline: Se o pattern deve processar múltiplas linhas

        Returns:
            Lista de tuplas (linha, coluna, texto_encontrado)

        Raises:
            PatternCompilationError: Se o pattern regex for inválido

        Example:
            >>> matcher = PatternMatcher()
            >>> matches = matcher.find_matches(
            ...     r'eval\s*\(',
            ...     'result = eval(user_input)',
            ...     'eval-usage'
            ... )
            >>> len(matches)
            1
        """
        try:
            # Compilar pattern (usa cache se já compilado)
            compiled_pattern = self._compile_pattern(
                pattern,
                case_sensitive,
                multiline
            )

            matches = []
            for match in compiled_pattern.finditer(code):
                # Calcular linha e coluna
                line_num = code[:match.start()].count('\n') + 1
                line_start = code[:match.start()].rfind('\n') + 1
                col_num = match.start() - line_start + 1

                matched_text = match.group(0)
                matches.append((line_num, col_num, matched_text))

            if matches:
                logger.debug(
                    f"Pattern {rule_id}: {len(matches)} match(es) encontrado(s)"
                )

            return matches

        except re.error as e:
            raise PatternCompilationError(
                f"Erro ao compilar pattern da regra {rule_id}",
                details=str(e)
            )

    def _compile_pattern(
        self,
        pattern: str,
        case_sensitive: bool,
        multiline: bool
    ) -> Pattern:
        """
        Compila um pattern regex com caching.

        Args:
            pattern: Expressão regular
            case_sensitive: Se deve ser case-sensitive
            multiline: Se deve processar múltiplas linhas

        Returns:
            Pattern compilado

        Raises:
            PatternCompilationError: Se o pattern for inválido
        """
        # Criar chave de cache
        cache_key = f"{pattern}:{case_sensitive}:{multiline}"

        # Retornar do cache se existir
        if cache_key in self._pattern_cache:
            return self._pattern_cache[cache_key]

        # Compilar pattern
        try:
            flags = 0
            if not case_sensitive:
                flags |= re.IGNORECASE
            if multiline:
                flags |= re.MULTILINE | re.DOTALL

            compiled = re.compile(pattern, flags)
            self._pattern_cache[cache_key] = compiled
            return compiled

        except re.error as e:
            raise PatternCompilationError(
                f"Erro ao compilar pattern regex: {pattern}",
                details=str(e)
            )

    def match_line(
        self,
        pattern: str,
        line: str,
        case_sensitive: bool = True
    ) -> Optional[re.Match]:
        """
        Verifica se uma linha específica corresponde ao pattern.

        Args:
            pattern: Expressão regular
            line: Linha de código
            case_sensitive: Se deve ser case-sensitive

        Returns:
            Match object ou None

        Example:
            >>> matcher = PatternMatcher()
            >>> match = matcher.match_line(r'exec\s*\(', 'exec(cmd)')
            >>> match is not None
            True
        """
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            return re.search(pattern, line, flags)
        except re.error as e:
            logger.error(f"Erro ao compilar pattern: {e}")
            return None

    def extract_groups(
        self,
        pattern: str,
        code: str,
        case_sensitive: bool = True
    ) -> List[Tuple[str, ...]]:
        """
        Extrai grupos de captura de um pattern.

        Args:
            pattern: Expressão regular com grupos de captura
            code: Código-fonte
            case_sensitive: Se deve ser case-sensitive

        Returns:
            Lista de tuplas com os grupos capturados

        Example:
            >>> matcher = PatternMatcher()
            >>> groups = matcher.extract_groups(
            ...     r'function\s+(\w+)\s*\(',
            ...     'function myFunc() { }'
            ... )
            >>> groups[0]
            ('myFunc',)
        """
        try:
            flags = 0 if case_sensitive else re.IGNORECASE
            compiled = re.compile(pattern, flags)

            results = []
            for match in compiled.finditer(code):
                if match.groups():
                    results.append(match.groups())

            return results

        except re.error as e:
            logger.error(f"Erro ao extrair grupos: {e}")
            return []

    def find_function_calls(
        self,
        function_name: str,
        code: str,
        language: str = 'python'
    ) -> List[Tuple[int, int, str]]:
        """
        Encontra chamadas de função específica no código.

        Args:
            function_name: Nome da função
            code: Código-fonte
            language: Linguagem (para ajustar pattern)

        Returns:
            Lista de tuplas (linha, coluna, código_chamada)

        Example:
            >>> matcher = PatternMatcher()
            >>> calls = matcher.find_function_calls('eval', code)
        """
        # Patterns por linguagem
        patterns = {
            'python': rf'\b{re.escape(function_name)}\s*\(',
            'javascript': rf'\b{re.escape(function_name)}\s*\(',
            'java': rf'\b{re.escape(function_name)}\s*\(',
            'c': rf'\b{re.escape(function_name)}\s*\(',
            'cpp': rf'\b{re.escape(function_name)}\s*\(',
        }

        pattern = patterns.get(language, rf'\b{re.escape(function_name)}\s*\(')

        return self.find_matches(
            pattern,
            code,
            f'function-call-{function_name}'
        )

    def find_imports(
        self,
        module_name: str,
        code: str,
        language: str = 'python'
    ) -> List[Tuple[int, int, str]]:
        """
        Encontra imports de módulo específico.

        Args:
            module_name: Nome do módulo
            code: Código-fonte
            language: Linguagem

        Returns:
            Lista de tuplas (linha, coluna, statement_import)
        """
        patterns = {
            'python': [
                rf'^\s*import\s+{re.escape(module_name)}\b',
                rf'^\s*from\s+{re.escape(module_name)}\s+import\b',
            ],
            'javascript': [
                rf'^\s*import\s+.*\s+from\s+[\'\"]{re.escape(module_name)}[\'\"]',
                rf'^\s*require\s*\(\s*[\'\"]{re.escape(module_name)}\s*[\'\"]',
            ],
            'java': [
                rf'^\s*import\s+{re.escape(module_name)}\b',
            ]
        }

        results = []
        for pattern in patterns.get(language, []):
            results.extend(
                self.find_matches(pattern, code, f'import-{module_name}')
            )

        return results

    def count_matches(
        self,
        pattern: str,
        code: str,
        case_sensitive: bool = True
    ) -> int:
        """
        Conta o número de matches de um pattern.

        Args:
            pattern: Expressão regular
            code: Código-fonte
            case_sensitive: Se deve ser case-sensitive

        Returns:
            Número de matches
        """
        matches = self.find_matches(
            pattern,
            code,
            'count',
            case_sensitive
        )
        return len(matches)

    def has_pattern(
        self,
        pattern: str,
        code: str,
        case_sensitive: bool = True
    ) -> bool:
        """
        Verifica se um pattern existe no código.

        Args:
            pattern: Expressão regular
            code: Código-fonte
            case_sensitive: Se deve ser case-sensitive

        Returns:
            True se encontrou pelo menos um match
        """
        return self.count_matches(pattern, code, case_sensitive) > 0

    def clear_cache(self) -> None:
        """Limpa o cache de patterns compilados"""
        self._pattern_cache.clear()
        logger.debug("Cache de patterns limpo")

    def get_cache_size(self) -> int:
        """Retorna o tamanho do cache"""
        return len(self._pattern_cache)
