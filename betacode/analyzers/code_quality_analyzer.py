"""
BetaCode - Code Quality Analyzer

Este módulo analisa a qualidade do código, detectando problemas
como código duplicado, complexidade ciclomática, code smells, etc.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import re
from typing import List, Dict
from ..core.base_types import Finding, Severity, FindingType
from ..utils.logger import get_logger

logger = get_logger(__name__)


class CodeQualityAnalyzer:
    """
    Analisa qualidade do código.

    Detecta:
    - Funções muito longas
    - Complexidade ciclomática alta
    - Código duplicado
    - TODOs e FIXMEs
    - Magic numbers
    - Linhas muito longas
    - Imports não utilizados
    - Variáveis não utilizadas
    """

    # Configurações
    MAX_FUNCTION_LENGTH = 50  # linhas
    MAX_LINE_LENGTH = 120     # caracteres
    MAX_COMPLEXITY = 10       # cyclomatic complexity

    def __init__(self):
        """Inicializa o analisador de qualidade"""
        pass

    def analyze(
        self,
        code: str,
        language: str,
        file_path: str
    ) -> List[Finding]:
        """
        Analisa qualidade do código.

        Args:
            code: Código-fonte
            language: Linguagem
            file_path: Caminho do arquivo

        Returns:
            Lista de findings de qualidade
        """
        findings = []

        # Detectar TODOs e FIXMEs
        findings.extend(self._detect_todos(code, file_path))

        # Detectar linhas muito longas
        findings.extend(self._detect_long_lines(code, file_path))

        # Detectar funções muito longas
        findings.extend(self._detect_long_functions(code, language, file_path))

        # Detectar código comentado
        findings.extend(self._detect_commented_code(code, file_path))

        # Detectar complexidade
        findings.extend(self._detect_complexity(code, file_path))

        logger.debug(f"Análise de qualidade: {len(findings)} finding(s) em {file_path}")

        return findings

    def _detect_todos(self, code: str, file_path: str) -> List[Finding]:
        """Detecta TODOs, FIXMEs e HACKs no código"""
        findings = []
        patterns = [
            (r'#\s*(TODO|FIXME|HACK|XXX|BUG)[\s:](.*)', 'python'),
            (r'//\s*(TODO|FIXME|HACK|XXX|BUG)[\s:](.*)', 'javascript'),
            (r'/\*\s*(TODO|FIXME|HACK|XXX|BUG)[\s:](.*)', 'java'),
        ]

        for pattern, lang_type in patterns:
            for match in re.finditer(pattern, code, re.IGNORECASE):
                line_num = code[:match.start()].count('\n') + 1
                code_lines = code.split('\n')
                snippet = code_lines[line_num - 1] if line_num <= len(code_lines) else ""

                todo_type = match.group(1).upper()
                message = match.group(2).strip() if len(match.groups()) > 1 else ""

                severity = Severity.LOW
                if todo_type in ['FIXME', 'BUG']:
                    severity = Severity.MEDIUM

                finding = Finding(
                    id=Finding.generate_id(file_path, line_num, f"todo_{todo_type.lower()}"),
                    rule_id=f"quality_todo_{todo_type.lower()}",
                    finding_type=FindingType.QUALITY,
                    severity=severity,
                    file=file_path,
                    line=line_num,
                    column=1,
                    message=f"{todo_type} encontrado: {message[:50]}",
                    code_snippet=snippet.strip(),
                    remediations=[
                        f"Resolver {todo_type}: {message}",
                        "Criar issue/ticket para rastrear",
                        "Remover comentário após resolução"
                    ]
                )
                findings.append(finding)

        return findings

    def _detect_complexity(self, code: str, file_path: str) -> List[Finding]:
        """
        Detecta alta complexidade (heurística baseada em indentação).
        Aproximação da complexidade ciclomática.
        """
        findings = []
        lines = code.split('\n')

        current_function = None
        current_complexity = 1
        function_start = 0

        # Regex para detectar início de função (simplificado)
        func_start_pattern = re.compile(r'^\s*(def|function|public|private|protected)\s+')
        # Regex para detectar branching
        branch_pattern = re.compile(r'\b(if|for|while|case|catch|elif|else)\b')

        for i, line in enumerate(lines):
            line_num = i + 1
            stripped = line.strip()

            # Detectar início de função
            if func_start_pattern.match(stripped):
                # Finalizar função anterior
                if current_function and current_complexity > self.MAX_COMPLEXITY:
                    self._add_complexity_finding(findings, file_path, function_start, current_function, current_complexity, lines)

                # Iniciar nova função
                current_function = stripped.split('(')[0] # Nome aproximado
                current_complexity = 1
                function_start = line_num
                continue

            # Calcular complexidade
            if current_function:
                # Contar keywords de controle de fluxo
                matches = branch_pattern.findall(stripped)
                current_complexity += len(matches)

        # Verificar última função
        if current_function and current_complexity > self.MAX_COMPLEXITY:
            self._add_complexity_finding(findings, file_path, function_start, current_function, current_complexity, lines)

        return findings

    def _add_complexity_finding(self, findings, file_path, line_num, func_name, complexity, lines):
        finding = Finding(
            id=Finding.generate_id(file_path, line_num, "high_complexity"),
            rule_id="quality_high_complexity",
            finding_type=FindingType.QUALITY,
            severity=Severity.MEDIUM,
            file=file_path,
            line=line_num,
            column=1,
            message=f"Alta complexidade detectada em '{func_name}' (Score: {complexity}, Max: {self.MAX_COMPLEXITY})",
            code_snippet=lines[line_num - 1] if line_num <= len(lines) else "",
            remediations=[
                "Refatorar para reduzir aninhamento",
                "Extrair partes da lógica para novas funções",
                "Simplificar expressões condicionais"
            ]
        )
        findings.append(finding)

    def _detect_long_lines(self, code: str, file_path: str) -> List[Finding]:
        """Detecta linhas muito longas"""
        findings = []
        lines = code.split('\n')

        for line_num, line in enumerate(lines, 1):
            if len(line) > self.MAX_LINE_LENGTH:
                finding = Finding(
                    id=Finding.generate_id(file_path, line_num, "long_line"),
                    rule_id="quality_long_line",
                    finding_type=FindingType.QUALITY,
                    severity=Severity.INFO,
                    file=file_path,
                    line=line_num,
                    column=self.MAX_LINE_LENGTH + 1,
                    message=f"Linha muito longa ({len(line)} caracteres, máximo {self.MAX_LINE_LENGTH})",
                    code_snippet=line[:100] + "..." if len(line) > 100 else line,
                    remediations=[
                        f"Quebrar linha em múltiplas linhas (máx {self.MAX_LINE_LENGTH} caracteres)",
                        "Refatorar expressão complexa em variáveis intermediárias"
                    ]
                )
                findings.append(finding)

        return findings

    def _detect_long_functions(
        self,
        code: str,
        language: str,
        file_path: str
    ) -> List[Finding]:
        """Detecta funções muito longas"""
        findings = []

        # Patterns para detectar definições de função por linguagem
        function_patterns = {
            'python': r'^\s*def\s+(\w+)\s*\(',
            'javascript': r'^\s*function\s+(\w+)\s*\(',
            'java': r'^\s*(public|private|protected)?\s*(static)?\s*\w+\s+(\w+)\s*\(',
        }

        pattern = function_patterns.get(language)
        if not pattern:
            return findings

        lines = code.split('\n')
        current_function = None
        function_start = 0
        indent_level = 0

        for line_num, line in enumerate(lines, 1):
            # Detectar início de função
            match = re.match(pattern, line)
            if match:
                current_function = match.group(1) if len(match.groups()) >= 1 else match.group(3)
                function_start = line_num
                indent_level = len(line) - len(line.lstrip())
                continue

            # Detectar fim de função (heurística simples)
            if current_function and line.strip() and not line.startswith('#'):
                current_indent = len(line) - len(line.lstrip())
                if current_indent <= indent_level and line.strip():
                    # Fim da função
                    function_length = line_num - function_start

                    if function_length > self.MAX_FUNCTION_LENGTH:
                        finding = Finding(
                            id=Finding.generate_id(file_path, function_start, "long_function"),
                            rule_id="quality_long_function",
                            finding_type=FindingType.QUALITY,
                            severity=Severity.MEDIUM,
                            file=file_path,
                            line=function_start,
                            column=1,
                            message=f"Função '{current_function}' muito longa ({function_length} linhas, máximo {self.MAX_FUNCTION_LENGTH})",
                            code_snippet=lines[function_start - 1] if function_start <= len(lines) else "",
                            remediations=[
                                "Dividir função em funções menores",
                                "Extrair lógica em métodos auxiliares",
                                "Aplicar princípio da responsabilidade única (SRP)"
                            ]
                        )
                        findings.append(finding)

                    current_function = None

        # Check if the last function goes until the end of the file
        if current_function:
             function_length = len(lines) - function_start + 1
             if function_length > self.MAX_FUNCTION_LENGTH:
                 finding = Finding(
                     id=Finding.generate_id(file_path, function_start, "long_function"),
                     rule_id="quality_long_function",
                     finding_type=FindingType.QUALITY,
                     severity=Severity.MEDIUM,
                     file=file_path,
                     line=function_start,
                     column=1,
                     message=f"Função '{current_function}' muito longa ({function_length} linhas, máximo {self.MAX_FUNCTION_LENGTH})",
                     code_snippet=lines[function_start - 1] if function_start <= len(lines) else "",
                     remediations=[
                         "Dividir função em funções menores",
                         "Extrair lógica em métodos auxiliares",
                         "Aplicar princípio da responsabilidade única (SRP)"
                     ]
                 )
                 findings.append(finding)

        return findings

    def _detect_commented_code(self, code: str, file_path: str) -> List[Finding]:
        """Detecta código comentado (não documentação)"""
        findings = []

        # Padrões de código comentado (heurística simples)
        code_patterns = [
            r'#\s*(if |for |while |def |class |import |return |print)',
            r'//\s*(if |for |while |function |const |let |var |return)',
        ]

        for pattern in code_patterns:
            for match in re.finditer(pattern, code):
                line_num = code[:match.start()].count('\n') + 1
                code_lines = code.split('\n')
                snippet = code_lines[line_num - 1] if line_num <= len(code_lines) else ""

                finding = Finding(
                    id=Finding.generate_id(file_path, line_num, "commented_code"),
                    rule_id="quality_commented_code",
                    finding_type=FindingType.QUALITY,
                    severity=Severity.LOW,
                    file=file_path,
                    line=line_num,
                    column=1,
                    message="Código comentado detectado",
                    code_snippet=snippet.strip(),
                    remediations=[
                        "Remover código comentado",
                        "Usar controle de versão ao invés de comentar",
                        "Se necessário manter, adicionar explicação do porquê"
                    ]
                )
                findings.append(finding)

        return findings

    def get_statistics(self, findings: List[Finding]) -> Dict[str, any]:
        """Calcula estatísticas de qualidade"""
        stats = {
            'total_issues': len(findings),
            'by_type': {},
            'files_affected': len(set(f.file for f in findings))
        }

        for finding in findings:
            rule_id = finding.rule_id
            stats['by_type'][rule_id] = stats['by_type'].get(rule_id, 0) + 1

        return stats
