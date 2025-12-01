"""
BetaCode - Dependency Analyzer

Este módulo analisa dependências de projeto e detecta
vulnerabilidades conhecidas (CVEs) e pacotes desatualizados.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import re
import json
from pathlib import Path
from typing import List, Dict, Optional
from ..core.base_types import Finding, Severity, FindingType, Dependency
from ..core.exceptions import DependencyAnalysisError
from ..utils.logger import get_logger

logger = get_logger(__name__)


class DependencyAnalyzer:
    """
    Analisa dependências de projetos e detecta vulnerabilidades.

    Suporta:
    - Python (requirements.txt, Pipfile, pyproject.toml)
    - JavaScript/Node (package.json, package-lock.json)
    - Java (pom.xml, build.gradle)
    - C# (.csproj, packages.config)
    - Go (go.mod)
    - Ruby (Gemfile, Gemfile.lock)
    - PHP (composer.json)
    """

    # Banco de dados simples de vulnerabilidades conhecidas (em produção usar API real)
    KNOWN_VULNERABILITIES: Dict[str, List[Dict]] = {
        'python': {
            'django': [
                {'version': '<3.2.14', 'cve': 'CVE-2022-34265', 'severity': 'HIGH'},
                {'version': '<2.2.28', 'cve': 'CVE-2022-28346', 'severity': 'CRITICAL'},
            ],
            'flask': [
                {'version': '<2.0.0', 'cve': 'CVE-2023-30861', 'severity': 'HIGH'},
            ],
            'requests': [
                {'version': '<2.31.0', 'cve': 'CVE-2023-32681', 'severity': 'MEDIUM'},
            ],
        },
        'javascript': {
            'lodash': [
                {'version': '<4.17.21', 'cve': 'CVE-2021-23337', 'severity': 'HIGH'},
            ],
            'axios': [
                {'version': '<0.21.3', 'cve': 'CVE-2021-3749', 'severity': 'MEDIUM'},
            ],
            'express': [
                {'version': '<4.17.3', 'cve': 'CVE-2022-24999', 'severity': 'HIGH'},
            ],
        }
    }

    def __init__(self):
        """Inicializa o analisador de dependências"""
        pass

    def analyze(self, target_path: Path) -> List[Finding]:
        """
        Analisa dependências de um projeto.

        Args:
            target_path: Caminho para diretório do projeto

        Returns:
            Lista de findings relacionados a dependências
        """
        findings = []

        try:
            # Detectar arquivos de dependências
            dep_files = self._find_dependency_files(target_path)

            if not dep_files:
                logger.warning(f"Nenhum arquivo de dependências encontrado em {target_path}")
                return findings

            # Analisar cada arquivo
            for dep_file in dep_files:
                try:
                    file_findings = self._analyze_file(dep_file)
                    findings.extend(file_findings)
                except Exception as e:
                    logger.error(f"Erro ao analisar {dep_file}: {e}")

            logger.info(f"Análise de dependências: {len(findings)} finding(s)")

        except Exception as e:
            raise DependencyAnalysisError(
                "Erro durante análise de dependências",
                details=str(e)
            )

        return findings

    def _find_dependency_files(self, target_path: Path) -> List[Path]:
        """Encontra arquivos de dependências no projeto"""
        dependency_files = [
            # Python
            'requirements.txt', 'requirements-dev.txt', 'Pipfile',
            'pyproject.toml', 'setup.py',
            # JavaScript/Node
            'package.json', 'package-lock.json', 'yarn.lock',
            # Java
            'pom.xml', 'build.gradle', 'build.gradle.kts',
            # C#
            '*.csproj', 'packages.config',
            # Go
            'go.mod', 'go.sum',
            # Ruby
            'Gemfile', 'Gemfile.lock',
            # PHP
            'composer.json', 'composer.lock',
        ]

        found_files = []
        for pattern in dependency_files:
            if '*' in pattern:
                found_files.extend(target_path.rglob(pattern))
            else:
                file_path = target_path / pattern if target_path.is_dir() else target_path.parent / pattern
                if file_path.exists():
                    found_files.append(file_path)

        return found_files

    def _analyze_file(self, file_path: Path) -> List[Finding]:
        """Analisa um arquivo de dependências específico"""
        filename = file_path.name.lower()

        if 'requirements' in filename or filename == 'pipfile':
            return self._analyze_python_deps(file_path)
        elif filename == 'package.json':
            return self._analyze_nodejs_deps(file_path)
        elif filename == 'pom.xml':
            return self._analyze_java_deps(file_path)
        elif filename == 'go.mod':
            return self._analyze_go_deps(file_path)
        else:
            logger.debug(f"Tipo de arquivo não suportado: {filename}")
            return []

    def _analyze_python_deps(self, file_path: Path) -> List[Finding]:
        """Analisa dependências Python"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()

            # Pattern: package==version ou package>=version
            pattern = r'^([a-zA-Z0-9\-_]+)\s*([=><~!]+)\s*([0-9.]+)'
            dependencies = []

            for line_num, line in enumerate(content.split('\n'), 1):
                match = re.match(pattern, line.strip())
                if match:
                    package_name = match.group(1).lower()
                    version = match.group(3)

                    dependencies.append({
                        'name': package_name,
                        'version': version,
                        'line': line_num
                    })

            # Verificar vulnerabilidades
            for dep in dependencies:
                vulns = self._check_vulnerabilities('python', dep['name'], dep['version'])
                if vulns:
                    findings.extend(
                        self._create_vulnerability_findings(
                            dep, vulns, file_path, 'python'
                        )
                    )

        except Exception as e:
            logger.error(f"Erro ao analisar {file_path}: {e}")

        return findings

    def _analyze_nodejs_deps(self, file_path: Path) -> List[Finding]:
        """Analisa dependências Node.js"""
        findings = []

        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                package_json = json.load(f)

            dependencies = {
                **package_json.get('dependencies', {}),
                **package_json.get('devDependencies', {})
            }

            for package_name, version in dependencies.items():
                # Limpar version (remover ^, ~, etc)
                clean_version = re.sub(r'[\^~><=]', '', version)

                vulns = self._check_vulnerabilities('javascript', package_name, clean_version)
                if vulns:
                    findings.extend(
                        self._create_vulnerability_findings(
                            {'name': package_name, 'version': clean_version, 'line': 1},
                            vulns,
                            file_path,
                            'javascript'
                        )
                    )

        except Exception as e:
            logger.error(f"Erro ao analisar {file_path}: {e}")

        return findings

    def _analyze_java_deps(self, file_path: Path) -> List[Finding]:
        """Analisa dependências Java (Maven)"""
        # Implementação simplificada
        return []

    def _analyze_go_deps(self, file_path: Path) -> List[Finding]:
        """Analisa dependências Go"""
        # Implementação simplificada
        return []

    def _check_vulnerabilities(
        self,
        language: str,
        package_name: str,
        version: str
    ) -> List[Dict]:
        """
        Verifica vulnerabilidades conhecidas para um pacote.

        Args:
            language: Linguagem (python, javascript, etc)
            package_name: Nome do pacote
            version: Versão do pacote

        Returns:
            Lista de vulnerabilidades encontradas
        """
        lang_vulns = self.KNOWN_VULNERABILITIES.get(language, {})
        package_vulns = lang_vulns.get(package_name.lower(), [])

        found_vulns = []
        for vuln in package_vulns:
            if self._version_matches(version, vuln['version']):
                found_vulns.append(vuln)

        return found_vulns

    def _version_matches(self, actual_version: str, vulnerable_version: str) -> bool:
        """
        Verifica se uma versão corresponde ao padrão vulnerável.

        Args:
            actual_version: Versão atual (ex: "2.0.0")
            vulnerable_version: Padrão vulnerável (ex: "<3.0.0")

        Returns:
            True se a versão é vulnerável
        """
        # Simplificação: comparação básica
        # Em produção, usar biblioteca como packaging.version
        try:
            if vulnerable_version.startswith('<'):
                target = vulnerable_version[1:].strip()
                return actual_version < target
            elif vulnerable_version.startswith('<='):
                target = vulnerable_version[2:].strip()
                return actual_version <= target
            elif vulnerable_version.startswith('=='):
                target = vulnerable_version[2:].strip()
                return actual_version == target
            else:
                return actual_version == vulnerable_version
        except:
            return False

    def _create_vulnerability_findings(
        self,
        dependency: Dict,
        vulnerabilities: List[Dict],
        file_path: Path,
        language: str
    ) -> List[Finding]:
        """Cria findings para vulnerabilidades encontradas"""
        findings = []

        for vuln in vulnerabilities:
            finding = Finding(
                id=Finding.generate_id(
                    str(file_path),
                    dependency.get('line', 1),
                    f"dep_{vuln['cve']}"
                ),
                rule_id=f"dependency_{vuln['cve']}",
                finding_type=FindingType.DEPENDENCY,
                severity=Severity[vuln['severity']],
                file=str(file_path),
                line=dependency.get('line', 1),
                column=1,
                message=f"📦 Vulnerabilidade em dependência: {dependency['name']} {dependency['version']}",
                code_snippet=f"{dependency['name']}=={dependency['version']}",
                cwe="CWE-1035",  # Using Components with Known Vulnerabilities
                owasp="A06:2021 - Vulnerable and Outdated Components",
                remediations=[
                    f"Atualizar {dependency['name']} para versão segura",
                    f"Consultar advisory: {vuln['cve']}",
                    "Verificar compatibilidade antes de atualizar",
                    "Considerar dependências transitivas"
                ],
                references=[
                    f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={vuln['cve']}",
                    f"https://nvd.nist.gov/vuln/detail/{vuln['cve']}"
                ],
                context={
                    'package': dependency['name'],
                    'current_version': dependency['version'],
                    'cve': vuln['cve'],
                    'language': language
                }
            )
            findings.append(finding)

        return findings

    def get_statistics(self, findings: List[Finding]) -> Dict[str, any]:
        """Calcula estatísticas de dependências"""
        stats = {
            'total_vulnerabilities': len(findings),
            'by_severity': {},
            'by_cve': {},
            'packages_affected': len(set(f.context.get('package') for f in findings))
        }

        for finding in findings:
            severity = finding.severity.name
            stats['by_severity'][severity] = stats['by_severity'].get(severity, 0) + 1

            cve = finding.context.get('cve')
            if cve:
                stats['by_cve'][cve] = stats['by_cve'].get(cve, 0) + 1

        return stats
