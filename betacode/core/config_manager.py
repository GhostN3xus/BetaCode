"""
BetaCode - Configuration Manager

Este módulo gerencia a configuração do BetaCode,
carregando e validando configurações de arquivos YAML.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import yaml
from pathlib import Path
from typing import Optional, Dict, Any
from .base_types import Config
from .exceptions import ConfigurationError
from ..utils.logger import get_logger

logger = get_logger(__name__)


class ConfigManager:
    """
    Gerencia configurações do BetaCode.

    Carrega configurações de:
    1. Arquivo padrão (betacode/config/default.yaml)
    2. Arquivo customizado (se fornecido)
    3. Variáveis de ambiente (override)
    """

    DEFAULT_CONFIG_PATH = Path(__file__).parent.parent / "config" / "default.yaml"

    def __init__(self, config_path: Optional[str] = None):
        """
        Inicializa o gerenciador de configuração.

        Args:
            config_path: Caminho para arquivo de configuração customizado (opcional)
        """
        self.config_path = Path(config_path) if config_path else None
        self._config: Optional[Config] = None

    def load(self) -> Config:
        """
        Carrega configuração.

        Returns:
            Objeto Config configurado

        Raises:
            ConfigurationError: Se houver erro ao carregar configuração
        """
        try:
            # Carregar configuração padrão
            default_config = self._load_default_config()

            # Carregar configuração customizada se fornecida
            if self.config_path and self.config_path.exists():
                logger.info(f"Carregando configuração customizada: {self.config_path}")
                custom_config = self._load_config_file(self.config_path)
                # Merge com configuração padrão
                merged_config = self._merge_configs(default_config, custom_config)
            else:
                merged_config = default_config

            # Criar objeto Config
            self._config = Config(**merged_config)

            # Validar configuração
            self._validate_config(self._config)

            logger.info("Configuração carregada com sucesso")
            return self._config

        except Exception as e:
            raise ConfigurationError(
                "Erro ao carregar configuração",
                details=str(e)
            )

    def _load_default_config(self) -> Dict[str, Any]:
        """Carrega configuração padrão"""
        if self.DEFAULT_CONFIG_PATH.exists():
            return self._load_config_file(self.DEFAULT_CONFIG_PATH)
        else:
            logger.warning("Arquivo de configuração padrão não encontrado, usando defaults")
            return self._get_hardcoded_defaults()

    def _load_config_file(self, file_path: Path) -> Dict[str, Any]:
        """
        Carrega configuração de arquivo YAML.

        Args:
            file_path: Caminho para arquivo YAML

        Returns:
            Dicionário com configuração

        Raises:
            ConfigurationError: Se houver erro ao ler arquivo
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                config = yaml.safe_load(f)
            return config or {}
        except yaml.YAMLError as e:
            raise ConfigurationError(
                f"Erro ao parsear YAML: {file_path}",
                details=str(e)
            )
        except FileNotFoundError:
            raise ConfigurationError(f"Arquivo não encontrado: {file_path}")

    def _get_hardcoded_defaults(self) -> Dict[str, Any]:
        """Retorna configuração padrão hardcoded"""
        return {
            'languages': ['python', 'javascript', 'java', 'go', 'php', 'ruby'],
            'timeout': 300,
            'workers': 4,
            'max_file_size': 10,
            'exclude_patterns': [
                '*.min.js',
                '*.min.css',
                'node_modules/**',
                '__pycache__/**',
                '.git/**',
                '.venv/**',
                'venv/**',
                '*.pyc',
                'dist/**',
                'build/**',
                '.next/**',
                'coverage/**',
            ],
            'severity_level': 'LOW',
            'fail_on_critical': True,
            'output_formats': ['json', 'html'],
            'output_directory': './betacode-reports',
            'integrations': {},
            'rules_path': None,
            'enable_secret_detection': True,
            'enable_dependency_analysis': True,
            'enable_quality_analysis': True,
        }

    def _merge_configs(
        self,
        default: Dict[str, Any],
        custom: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Merge configurações (custom override default).

        Args:
            default: Configuração padrão
            custom: Configuração customizada

        Returns:
            Configuração merged
        """
        merged = default.copy()

        for key, value in custom.items():
            if isinstance(value, dict) and key in merged and isinstance(merged[key], dict):
                # Merge recursivo para dicts
                merged[key] = self._merge_configs(merged[key], value)
            elif isinstance(value, list) and key in merged and isinstance(merged[key], list):
                # Extend para listas
                merged[key] = merged[key] + value
            else:
                # Override para outros tipos
                merged[key] = value

        return merged

    def _validate_config(self, config: Config) -> None:
        """
        Valida configuração.

        Args:
            config: Configuração para validar

        Raises:
            ConfigurationError: Se configuração for inválida
        """
        # Validar workers
        if config.workers < 1:
            raise ConfigurationError("workers deve ser >= 1")

        # Validar timeout
        if config.timeout < 1:
            raise ConfigurationError("timeout deve ser >= 1")

        # Validar max_file_size
        if config.max_file_size < 1:
            raise ConfigurationError("max_file_size deve ser >= 1")

        # Validar severity_level
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if config.severity_level.upper() not in valid_severities:
            raise ConfigurationError(
                f"severity_level inválido: {config.severity_level}. "
                f"Deve ser um de: {valid_severities}"
            )

        # Validar output_formats
        valid_formats = ['json', 'html', 'sarif', 'pdf', 'markdown', 'csv']
        for fmt in config.output_formats:
            if fmt.lower() not in valid_formats:
                raise ConfigurationError(
                    f"Formato de output inválido: {fmt}. "
                    f"Deve ser um de: {valid_formats}"
                )

        logger.debug("Configuração validada com sucesso")

    def get_config(self) -> Optional[Config]:
        """Retorna configuração carregada"""
        return self._config

    def save_config(self, config: Config, file_path: Path) -> None:
        """
        Salva configuração em arquivo YAML.

        Args:
            config: Configuração para salvar
            file_path: Caminho para salvar

        Raises:
            ConfigurationError: Se houver erro ao salvar
        """
        try:
            file_path.parent.mkdir(parents=True, exist_ok=True)

            with open(file_path, 'w', encoding='utf-8') as f:
                yaml.dump(config.to_dict(), f, default_flow_style=False, allow_unicode=True)

            logger.info(f"Configuração salva em: {file_path}")

        except Exception as e:
            raise ConfigurationError(
                f"Erro ao salvar configuração em {file_path}",
                details=str(e)
            )
