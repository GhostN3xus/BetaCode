"""
BetaCode - Motor Principal

Este módulo contém o motor principal (BetaCodeEngine) que orquestra
toda a análise estática de código.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import List, Dict, Callable, Optional
from datetime import datetime
import fnmatch

from .base_types import Finding, AnalysisResult, Config, Severity
from .rule_engine import RuleEngine
from .config_manager import ConfigManager
from .exceptions import AnalysisError, FileReadError
from ..analyzers.language_detector import LanguageDetector
from ..analyzers.sast_analyzer import SASTAnalyzer
from ..analyzers.secret_detector import SecretDetector
from ..analyzers.dependency_analyzer import DependencyAnalyzer
from ..analyzers.code_quality_analyzer import CodeQualityAnalyzer
from ..utils.logger import get_logger

logger = get_logger(__name__)


class BetaCodeEngine:
    """
    Motor principal do BetaCode que orquestra toda a análise.

    Responsável por:
    - Coordenar analisadores (SAST, Secrets, Dependencies, Quality)
    - Executar análise paralela de arquivos
    - Consolidar findings
    - Calcular métricas
    - Gerenciar configuração e regras
    """

    VERSION = "1.0.0"

    def __init__(self, config_path: Optional[str] = None):
        """
        Inicializa o motor BetaCode.

        Args:
            config_path: Caminho para arquivo de configuração (opcional)
        """
        logger.info(f"Inicializando BetaCode v{self.VERSION}")

        # Carregar configuração
        self.config_manager = ConfigManager(config_path)
        self.config = self.config_manager.load()

        # Inicializar motor de regras
        self.rule_engine = RuleEngine(self.config)

        # Inicializar analisadores
        self.sast_analyzer = SASTAnalyzer(self.rule_engine)
        self.secret_detector = SecretDetector()
        self.quality_analyzer = CodeQualityAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()

        # Estado
        self.findings: List[Finding] = []
        self.metrics: Dict = {}
        self.errors: List[str] = []

        logger.info("BetaCode inicializado com sucesso")

    def analyze(
        self,
        target: str,
        progress_callback: Optional[Callable[[int, int], None]] = None
    ) -> AnalysisResult:
        """
        Método principal: analisa arquivo ou diretório.

        Args:
            target: Caminho do arquivo ou diretório para analisar
            progress_callback: Função para reportar progresso (current, total)

        Returns:
            AnalysisResult com todos os findings e métricas

        Raises:
            AnalysisError: Se ocorrer erro crítico durante análise
        """
        start_time = time.time()
        logger.info(f"=" * 60)
        logger.info(f"Iniciando análise BetaCode: {target}")
        logger.info(f"=" * 60)

        # Validar target
        target_path = Path(target)
        if not target_path.exists():
            raise AnalysisError(f"Target não encontrado: {target}")

        # Resetar estado
        self.findings = []
        self.errors = []

        try:
            # Coletar arquivos para análise
            files_to_analyze = self._collect_files(target_path)
            total_files = len(files_to_analyze)

            if total_files == 0:
                logger.warning("Nenhum arquivo encontrado para análise")
                return self._create_empty_result(target, start_time)

            logger.info(f"📁 Arquivos encontrados: {total_files}")
            logger.info(f"⚙️  Workers: {self.config.workers}")

            # Análise paralela de arquivos individuais
            logger.info("🔍 Executando análise paralela...")
            file_findings = self._analyze_parallel(files_to_analyze, progress_callback)
            self.findings.extend(file_findings)

            # Análise de dependências (nível de projeto)
            if self.config.enable_dependency_analysis:
                logger.info("📦 Analisando dependências...")
                try:
                    dep_findings = self.dependency_analyzer.analyze(target_path)
                    self.findings.extend(dep_findings)
                    logger.info(f"   Dependências: {len(dep_findings)} finding(s)")
                except Exception as e:
                    error_msg = f"Erro na análise de dependências: {e}"
                    logger.error(error_msg)
                    self.errors.append(error_msg)

            # Processamento pós-análise
            logger.info("🔄 Processando findings...")
            self.findings = self._deduplicate(self.findings)
            self.findings = self._normalize(self.findings)
            self.findings = self._filter_by_severity(self.findings)

            # Calcular métricas
            duration = time.time() - start_time
            self.metrics = self._calculate_metrics(self.findings, duration, total_files)

            # Criar resultado
            result = AnalysisResult(
                timestamp=datetime.now().isoformat(),
                target=target,
                total_findings=len(self.findings),
                findings=self.findings,
                metrics=self.metrics,
                duration_seconds=duration,
                files_scanned=total_files,
                files_failed=len(self.errors),
                errors=self.errors,
                version=self.VERSION,
                config=self.config.to_dict()
            )

            # Log sumário
            self._log_summary(result)

            return result

        except Exception as e:
            logger.error(f"Erro durante análise: {e}")
            raise AnalysisError(
                f"Erro durante análise de {target}",
                details=str(e)
            )

    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Analisa um arquivo único.

        Args:
            file_path: Caminho do arquivo

        Returns:
            Lista de findings para este arquivo
        """
        findings = []

        try:
            # Detectar linguagem
            language = LanguageDetector.detect(file_path)

            if language == 'unknown':
                logger.debug(f"Linguagem desconhecida: {file_path}")
                return findings

            if not LanguageDetector.is_supported(language):
                logger.debug(f"Linguagem não suportada: {language} ({file_path})")
                return findings

            # Ler código
            try:
                with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                    code = f.read()
            except Exception as e:
                error_msg = f"Erro ao ler {file_path}: {e}"
                logger.error(error_msg)
                self.errors.append(error_msg)
                return findings

            # Verificar tamanho do arquivo
            file_size_mb = len(code) / (1024 * 1024)
            if file_size_mb > self.config.max_file_size:
                logger.warning(
                    f"Arquivo muito grande ({file_size_mb:.2f}MB): {file_path} (ignorado)"
                )
                return findings

            # Análise SAST
            try:
                sast_findings = self.sast_analyzer.analyze(code, language, file_path)
                findings.extend(sast_findings)
            except Exception as e:
                logger.error(f"Erro na análise SAST de {file_path}: {e}")

            # Detecção de Secrets
            if self.config.enable_secret_detection:
                try:
                    secret_findings = self.secret_detector.detect(code, file_path)
                    findings.extend(secret_findings)
                except Exception as e:
                    logger.error(f"Erro na detecção de secrets de {file_path}: {e}")

            # Análise de Qualidade
            if self.config.enable_quality_analysis:
                try:
                    quality_findings = self.quality_analyzer.analyze(code, language, file_path)
                    findings.extend(quality_findings)
                except Exception as e:
                    logger.error(f"Erro na análise de qualidade de {file_path}: {e}")

            logger.debug(f"✓ {file_path}: {len(findings)} finding(s)")

        except Exception as e:
            error_msg = f"Erro ao analisar {file_path}: {e}"
            logger.error(error_msg)
            self.errors.append(error_msg)

        return findings

    def _collect_files(self, target_path: Path) -> List[Path]:
        """
        Coleta todos os arquivos a analisar.

        Args:
            target_path: Caminho alvo

        Returns:
            Lista de arquivos para analisar
        """
        if target_path.is_file():
            return [target_path]

        # Coletar arquivos do diretório
        all_files = []
        supported_extensions = LanguageDetector.get_supported_extensions()

        for ext in supported_extensions:
            pattern = f"**/*{ext}"
            found = list(target_path.glob(pattern))
            all_files.extend(found)

        # Filtrar por exclude_patterns
        filtered_files = []
        for file_path in all_files:
            if not self._is_excluded(file_path):
                filtered_files.append(file_path)

        logger.info(f"Arquivos após filtros: {len(filtered_files)}/{len(all_files)}")
        return filtered_files

    def _is_excluded(self, file_path: Path) -> bool:
        """Verifica se arquivo deve ser excluído"""
        file_str = str(file_path)

        for pattern in self.config.exclude_patterns:
            if fnmatch.fnmatch(file_str, f"*{pattern}*"):
                return True

        return False

    def _analyze_parallel(
        self,
        files: List[Path],
        progress_callback: Optional[Callable]
    ) -> List[Finding]:
        """
        Executa análise em paralelo usando ThreadPoolExecutor.

        Args:
            files: Lista de arquivos para analisar
            progress_callback: Callback para progresso

        Returns:
            Lista consolidada de findings
        """
        findings = []
        completed = 0

        with ThreadPoolExecutor(max_workers=self.config.workers) as executor:
            # Submeter todas as tarefas
            futures = {
                executor.submit(self.scan_file, str(file)): file
                for file in files
            }

            # Processar resultados conforme completam
            for future in as_completed(futures):
                file_path = futures[future]

                try:
                    file_findings = future.result(timeout=self.config.timeout)
                    findings.extend(file_findings)
                except TimeoutError:
                    error_msg = f"Timeout ao analisar: {file_path}"
                    logger.error(error_msg)
                    self.errors.append(error_msg)
                except Exception as e:
                    error_msg = f"Erro ao analisar {file_path}: {e}"
                    logger.error(error_msg)
                    self.errors.append(error_msg)

                completed += 1

                # Reportar progresso
                if progress_callback:
                    progress_callback(completed, len(files))

                # Log periódico
                if completed % 10 == 0 or completed == len(files):
                    logger.info(f"Progresso: {completed}/{len(files)} arquivos")

        return findings

    def _deduplicate(self, findings: List[Finding]) -> List[Finding]:
        """
        Remove findings duplicados.

        Args:
            findings: Lista de findings

        Returns:
            Lista sem duplicados
        """
        seen = set()
        unique_findings = []

        for finding in findings:
            # Criar chave única: (file, line, rule_id)
            key = (finding.file, finding.line, finding.rule_id)

            if key not in seen:
                seen.add(key)
                unique_findings.append(finding)

        if len(findings) > len(unique_findings):
            logger.info(
                f"Removidos {len(findings) - len(unique_findings)} findings duplicados"
            )

        return unique_findings

    def _normalize(self, findings: List[Finding]) -> List[Finding]:
        """
        Normaliza findings (ordena por severidade/file/line).

        Args:
            findings: Lista de findings

        Returns:
            Lista normalizada
        """
        # Ordenar por: severidade (desc), arquivo, linha
        sorted_findings = sorted(
            findings,
            key=lambda f: (-f.severity.value, f.file, f.line)
        )

        return sorted_findings

    def _filter_by_severity(self, findings: List[Finding]) -> List[Finding]:
        """Filtra findings por nível mínimo de severidade"""
        min_severity = Severity[self.config.severity_level.upper()]

        filtered = [
            f for f in findings
            if f.severity.value >= min_severity.value
        ]

        if len(filtered) < len(findings):
            logger.info(
                f"Filtrados {len(findings) - len(filtered)} findings "
                f"abaixo de {min_severity.name}"
            )

        return filtered

    def _calculate_metrics(
        self,
        findings: List[Finding],
        duration: float,
        files_count: int
    ) -> Dict:
        """
        Calcula métricas da análise.

        Args:
            findings: Findings encontrados
            duration: Duração em segundos
            files_count: Número de arquivos analisados

        Returns:
            Dicionário com métricas
        """
        # Contagem por severidade
        by_severity = {}
        for finding in findings:
            sev = finding.severity.name
            by_severity[sev] = by_severity.get(sev, 0) + 1

        # Contagem por tipo
        by_type = {}
        for finding in findings:
            ftype = finding.finding_type.value
            by_type[ftype] = by_type.get(ftype, 0) + 1

        # Risk score (weighted by severity)
        risk_score = (
            by_severity.get('CRITICAL', 0) * 100 +
            by_severity.get('HIGH', 0) * 50 +
            by_severity.get('MEDIUM', 0) * 20 +
            by_severity.get('LOW', 0) * 5
        ) / max(files_count, 1)

        # Normalizar risk_score (0-100)
        risk_score = min(100, risk_score)

        return {
            'total_findings': len(findings),
            'by_severity': by_severity,
            'by_type': by_type,
            'risk_score': round(risk_score, 2),
            'duration_seconds': round(duration, 2),
            'files_scanned': files_count,
            'findings_per_file': round(len(findings) / max(files_count, 1), 2),
            'errors': len(self.errors)
        }

    def _create_empty_result(self, target: str, start_time: float) -> AnalysisResult:
        """Cria resultado vazio quando não há arquivos"""
        return AnalysisResult(
            timestamp=datetime.now().isoformat(),
            target=target,
            total_findings=0,
            findings=[],
            metrics={'risk_score': 0},
            duration_seconds=time.time() - start_time,
            files_scanned=0
        )

    def _log_summary(self, result: AnalysisResult) -> None:
        """Loga sumário da análise"""
        logger.info("")
        logger.info("=" * 60)
        logger.info("📊 SUMÁRIO DA ANÁLISE")
        logger.info("=" * 60)
        logger.info(f"⏱️  Duração: {result.duration_seconds:.2f}s")
        logger.info(f"📁 Arquivos: {result.files_scanned}")
        logger.info(f"🔍 Findings: {result.total_findings}")

        if result.metrics.get('by_severity'):
            logger.info("📈 Por Severidade:")
            for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']:
                count = result.metrics['by_severity'].get(sev, 0)
                if count > 0:
                    logger.info(f"   {sev}: {count}")

        risk_score = result.metrics.get('risk_score', 0)
        logger.info(f"⚠️  Risk Score: {risk_score}/100")

        if result.errors:
            logger.warning(f"❌ Erros: {len(result.errors)}")

        logger.info("=" * 60)

    def get_summary(self) -> Dict:
        """
        Retorna sumário da última análise.

        Returns:
            Dicionário com sumário
        """
        return {
            'total_findings': len(self.findings),
            'metrics': self.metrics,
            'by_severity': self._group_by_severity(),
            'by_type': self._group_by_type()
        }

    def _group_by_severity(self) -> Dict[str, int]:
        """Agrupa findings por severidade"""
        grouped = {}
        for finding in self.findings:
            sev = finding.severity.name
            grouped[sev] = grouped.get(sev, 0) + 1
        return grouped

    def _group_by_type(self) -> Dict[str, int]:
        """Agrupa findings por tipo"""
        grouped = {}
        for finding in self.findings:
            ftype = finding.finding_type.value
            grouped[ftype] = grouped.get(ftype, 0) + 1
        return grouped
