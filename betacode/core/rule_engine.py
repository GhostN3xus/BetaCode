"""
BetaCode - Motor de Regras

Este módulo gerencia o carregamento, validação e execução de regras
de detecção de vulnerabilidades a partir de arquivos YAML.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import yaml
from pathlib import Path
from typing import List, Dict, Optional, Any
from .base_types import Rule, Config
from .exceptions import (
    RuleLoadError,
    RuleValidationError,
    FileReadError
)
from ..utils.logger import get_logger

logger = get_logger(__name__)


class RuleEngine:
    """
    Gerencia regras de análise estática.

    Responsável por:
    - Carregar regras de arquivos YAML
    - Validar estrutura das regras
    - Filtrar regras por linguagem
    - Habilitar/desabilitar regras
    """

    def __init__(self, config: Config):
        """
        Inicializa o motor de regras.

        Args:
            config: Configuração do BetaCode
        """
        self.config = config
        self.rules: List[Rule] = []
        self._rules_by_language: Dict[str, List[Rule]] = {}
        self._rules_by_id: Dict[str, Rule] = {}
        self._load_rules()

    def _load_rules(self) -> None:
        """Carrega todas as regras disponíveis"""
        try:
            # Diretório de regras
            rules_dir = Path(__file__).parent.parent / "rules" / "custom"

            if not rules_dir.exists():
                logger.warning(f"Diretório de regras não encontrado: {rules_dir}")
                rules_dir.mkdir(parents=True, exist_ok=True)
                return

            # Carregar arquivos YAML
            yaml_files = list(rules_dir.glob("*.yaml")) + list(rules_dir.glob("*.yml"))

            if not yaml_files:
                logger.warning("Nenhum arquivo de regras encontrado")
                return

            for yaml_file in yaml_files:
                try:
                    rules = self._load_rules_from_file(yaml_file)
                    self.rules.extend(rules)
                    logger.info(f"Carregadas {len(rules)} regras de {yaml_file.name}")
                except Exception as e:
                    logger.error(f"Erro ao carregar {yaml_file}: {e}")

            # Indexar regras
            self._index_rules()

            logger.info(f"Total de {len(self.rules)} regras carregadas")

        except Exception as e:
            raise RuleLoadError(
                "Erro ao carregar regras",
                details=str(e)
            )

    def _load_rules_from_file(self, file_path: Path) -> List[Rule]:
        """
        Carrega regras de um arquivo YAML.

        Args:
            file_path: Caminho para arquivo YAML

        Returns:
            Lista de regras carregadas

        Raises:
            FileReadError: Se não conseguir ler o arquivo
            RuleValidationError: Se a regra for inválida
        """
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                data = yaml.safe_load(f)

            if not data or 'rules' not in data:
                logger.warning(f"Arquivo {file_path} não contém regras")
                return []

            rules = []
            for rule_data in data['rules']:
                try:
                    rule = self._create_rule_from_dict(rule_data)
                    self._validate_rule(rule)
                    rules.append(rule)
                except RuleValidationError as e:
                    logger.error(f"Regra inválida em {file_path}: {e}")
                    continue

            return rules

        except yaml.YAMLError as e:
            raise FileReadError(
                f"Erro ao parsear YAML: {file_path}",
                details=str(e)
            )
        except FileNotFoundError:
            raise FileReadError(f"Arquivo não encontrado: {file_path}")

    def _create_rule_from_dict(self, data: Dict[str, Any]) -> Rule:
        """
        Cria objeto Rule a partir de dicionário.

        Args:
            data: Dicionário com dados da regra

        Returns:
            Objeto Rule

        Raises:
            RuleValidationError: Se campos obrigatórios estiverem faltando
        """
        required_fields = ['id', 'name', 'description', 'pattern', 'severity', 'language']

        for field in required_fields:
            if field not in data:
                raise RuleValidationError(
                    f"Campo obrigatório ausente: {field}",
                    details=data
                )

        return Rule(
            id=data['id'],
            name=data['name'],
            description=data['description'],
            pattern=data['pattern'],
            severity=data['severity'].upper(),
            language=data['language'].lower(),
            cwe=data.get('cwe'),
            owasp=data.get('owasp'),
            message_template=data.get('message_template', data['description']),
            remediation=data.get('remediation'),
            references=data.get('references', []),
            enabled=data.get('enabled', True),
            tags=data.get('tags', []),
            category=data.get('category', 'security')
        )

    def _validate_rule(self, rule: Rule) -> None:
        """
        Valida uma regra.

        Args:
            rule: Regra para validar

        Raises:
            RuleValidationError: Se a regra for inválida
        """
        # Validar severity
        valid_severities = ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFO']
        if rule.severity not in valid_severities:
            raise RuleValidationError(
                f"Severity inválida: {rule.severity}. Deve ser uma de: {valid_severities}"
            )

        # Validar pattern (tentar compilar como regex)
        try:
            import re
            re.compile(rule.pattern)
        except re.error as e:
            raise RuleValidationError(
                f"Pattern regex inválido na regra {rule.id}",
                details=str(e)
            )

        # Validar ID único
        if rule.id in self._rules_by_id:
            raise RuleValidationError(
                f"ID duplicado: {rule.id}"
            )

    def _index_rules(self) -> None:
        """Indexa regras por linguagem e ID para busca rápida"""
        self._rules_by_language.clear()
        self._rules_by_id.clear()

        for rule in self.rules:
            # Índice por linguagem
            if rule.language not in self._rules_by_language:
                self._rules_by_language[rule.language] = []
            self._rules_by_language[rule.language].append(rule)

            # Índice por ID
            self._rules_by_id[rule.id] = rule

    def get_rules_for_language(self, language: str) -> List[Rule]:
        """
        Retorna regras para uma linguagem específica.

        Args:
            language: Nome da linguagem

        Returns:
            Lista de regras para a linguagem
        """
        language = language.lower()
        return self._rules_by_language.get(language, [])

    def get_rule_by_id(self, rule_id: str) -> Optional[Rule]:
        """
        Retorna uma regra pelo ID.

        Args:
            rule_id: ID da regra

        Returns:
            Regra ou None se não encontrada
        """
        return self._rules_by_id.get(rule_id)

    def get_all_rules(self) -> List[Rule]:
        """Retorna todas as regras carregadas"""
        return self.rules.copy()

    def get_enabled_rules(self) -> List[Rule]:
        """Retorna apenas regras habilitadas"""
        return [rule for rule in self.rules if rule.enabled]

    def enable_rule(self, rule_id: str) -> bool:
        """
        Habilita uma regra.

        Args:
            rule_id: ID da regra

        Returns:
            True se habilitou, False se regra não encontrada
        """
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = True
            logger.info(f"Regra habilitada: {rule_id}")
            return True
        return False

    def disable_rule(self, rule_id: str) -> bool:
        """
        Desabilita uma regra.

        Args:
            rule_id: ID da regra

        Returns:
            True se desabilitou, False se regra não encontrada
        """
        rule = self.get_rule_by_id(rule_id)
        if rule:
            rule.enabled = False
            logger.info(f"Regra desabilitada: {rule_id}")
            return True
        return False

    def filter_rules(
        self,
        languages: Optional[List[str]] = None,
        severities: Optional[List[str]] = None,
        categories: Optional[List[str]] = None,
        tags: Optional[List[str]] = None,
        enabled_only: bool = True
    ) -> List[Rule]:
        """
        Filtra regras por critérios.

        Args:
            languages: Linguagens para filtrar
            severities: Severidades para filtrar
            categories: Categorias para filtrar
            tags: Tags para filtrar
            enabled_only: Se deve retornar apenas regras habilitadas

        Returns:
            Lista de regras filtradas
        """
        filtered = self.rules

        if enabled_only:
            filtered = [r for r in filtered if r.enabled]

        if languages:
            languages_lower = [lang.lower() for lang in languages]
            filtered = [r for r in filtered if r.language in languages_lower]

        if severities:
            severities_upper = [sev.upper() for sev in severities]
            filtered = [r for r in filtered if r.severity in severities_upper]

        if categories:
            categories_lower = [cat.lower() for cat in categories]
            filtered = [r for r in filtered if r.category in categories_lower]

        if tags:
            tags_lower = [tag.lower() for tag in tags]
            filtered = [
                r for r in filtered
                if any(tag in tags_lower for tag in [t.lower() for t in r.tags])
            ]

        return filtered

    def get_rules_statistics(self) -> Dict[str, Any]:
        """
        Retorna estatísticas sobre as regras carregadas.

        Returns:
            Dicionário com estatísticas
        """
        stats = {
            'total_rules': len(self.rules),
            'enabled_rules': len(self.get_enabled_rules()),
            'disabled_rules': len(self.rules) - len(self.get_enabled_rules()),
            'by_language': {},
            'by_severity': {},
            'by_category': {}
        }

        for rule in self.rules:
            # Por linguagem
            stats['by_language'][rule.language] = \
                stats['by_language'].get(rule.language, 0) + 1

            # Por severity
            stats['by_severity'][rule.severity] = \
                stats['by_severity'].get(rule.severity, 0) + 1

            # Por categoria
            stats['by_category'][rule.category] = \
                stats['by_category'].get(rule.category, 0) + 1

        return stats

    def reload_rules(self) -> None:
        """Recarrega todas as regras"""
        logger.info("Recarregando regras...")
        self.rules.clear()
        self._rules_by_language.clear()
        self._rules_by_id.clear()
        self._load_rules()
        logger.info("Regras recarregadas")
