"""
BetaCode - Detector de Linguagem de Programação

Este módulo detecta a linguagem de programação de um arquivo
baseado em sua extensão e conteúdo.

Author: BetaCode Team
License: MIT
Version: 1.0.0
"""

import re
from pathlib import Path
from typing import Optional, Dict, List
from ..utils.logger import get_logger

logger = get_logger(__name__)


class LanguageDetector:
    """
    Detecta a linguagem de programação de arquivos de código.

    Suporta 15+ linguagens através de extensões de arquivo e
    análise de conteúdo (shebangs, magic strings).
    """

    # Mapeamento de extensões para linguagens
    EXTENSIONS: Dict[str, str] = {
        # Python
        '.py': 'python',
        '.pyw': 'python',
        '.pyi': 'python',

        # JavaScript/TypeScript
        '.js': 'javascript',
        '.jsx': 'javascript',
        '.ts': 'typescript',
        '.tsx': 'typescript',
        '.mjs': 'javascript',
        '.cjs': 'javascript',

        # Java
        '.java': 'java',

        # C/C++
        '.c': 'c',
        '.h': 'c',
        '.cpp': 'cpp',
        '.cc': 'cpp',
        '.cxx': 'cpp',
        '.hpp': 'cpp',
        '.hh': 'cpp',
        '.hxx': 'cpp',

        # C#
        '.cs': 'csharp',

        # Go
        '.go': 'go',

        # Rust
        '.rs': 'rust',

        # Ruby
        '.rb': 'ruby',
        '.erb': 'ruby',

        # PHP
        '.php': 'php',
        '.php3': 'php',
        '.php4': 'php',
        '.php5': 'php',
        '.phtml': 'php',

        # Swift
        '.swift': 'swift',

        # Kotlin
        '.kt': 'kotlin',
        '.kts': 'kotlin',

        # Scala
        '.scala': 'scala',
        '.sc': 'scala',

        # Perl
        '.pl': 'perl',
        '.pm': 'perl',

        # Shell
        '.sh': 'shell',
        '.bash': 'shell',
        '.zsh': 'shell',

        # PowerShell
        '.ps1': 'powershell',
        '.psm1': 'powershell',

        # SQL
        '.sql': 'sql',

        # YAML
        '.yaml': 'yaml',
        '.yml': 'yaml',

        # JSON
        '.json': 'json',

        # XML
        '.xml': 'xml',

        # HTML
        '.html': 'html',
        '.htm': 'html',

        # CSS
        '.css': 'css',
        '.scss': 'scss',
        '.sass': 'sass',
        '.less': 'less',

        # Markdown
        '.md': 'markdown',
        '.markdown': 'markdown',
    }

    # Padrões de shebang para detecção por conteúdo
    SHEBANG_PATTERNS: Dict[str, str] = {
        r'#!/usr/bin/env python': 'python',
        r'#!/usr/bin/python': 'python',
        r'#!/usr/bin/env node': 'javascript',
        r'#!/usr/bin/node': 'javascript',
        r'#!/bin/bash': 'shell',
        r'#!/bin/sh': 'shell',
        r'#!/usr/bin/env bash': 'shell',
        r'#!/usr/bin/env sh': 'shell',
        r'#!/usr/bin/env ruby': 'ruby',
        r'#!/usr/bin/ruby': 'ruby',
        r'#!/usr/bin/env perl': 'perl',
        r'#!/usr/bin/perl': 'perl',
        r'#!/usr/bin/env php': 'php',
    }

    # Linguagens suportadas para análise SAST
    SUPPORTED_LANGUAGES: List[str] = [
        'python', 'javascript', 'typescript', 'java', 'c', 'cpp',
        'csharp', 'go', 'rust', 'ruby', 'php', 'swift', 'kotlin',
        'scala', 'shell', 'sql'
    ]

    @classmethod
    def detect(cls, file_path: str) -> str:
        """
        Detecta a linguagem de programação de um arquivo.

        Args:
            file_path: Caminho para o arquivo

        Returns:
            Nome da linguagem detectada (lowercase) ou 'unknown'

        Example:
            >>> LanguageDetector.detect('example.py')
            'python'
            >>> LanguageDetector.detect('script.js')
            'javascript'
        """
        path = Path(file_path)

        # Detectar por extensão
        extension = path.suffix.lower()
        if extension in cls.EXTENSIONS:
            language = cls.EXTENSIONS[extension]
            logger.debug(f"Linguagem detectada por extensão: {language} ({file_path})")
            return language

        # Detectar por conteúdo (shebang)
        try:
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                first_line = f.readline().strip()
                language = cls._detect_by_shebang(first_line)
                if language:
                    logger.debug(f"Linguagem detectada por shebang: {language} ({file_path})")
                    return language
        except Exception as e:
            logger.warning(f"Erro ao ler arquivo para detecção: {e}")

        logger.warning(f"Linguagem não detectada para: {file_path}")
        return 'unknown'

    @classmethod
    def _detect_by_shebang(cls, first_line: str) -> Optional[str]:
        """
        Detecta linguagem pelo shebang na primeira linha.

        Args:
            first_line: Primeira linha do arquivo

        Returns:
            Nome da linguagem ou None
        """
        for pattern, language in cls.SHEBANG_PATTERNS.items():
            if re.match(pattern, first_line):
                return language
        return None

    @classmethod
    def is_supported(cls, language: str) -> bool:
        """
        Verifica se uma linguagem é suportada para análise.

        Args:
            language: Nome da linguagem

        Returns:
            True se suportada, False caso contrário

        Example:
            >>> LanguageDetector.is_supported('python')
            True
            >>> LanguageDetector.is_supported('brainfuck')
            False
        """
        return language.lower() in cls.SUPPORTED_LANGUAGES

    @classmethod
    def get_supported_languages(cls) -> List[str]:
        """
        Retorna lista de linguagens suportadas.

        Returns:
            Lista de nomes de linguagens
        """
        return cls.SUPPORTED_LANGUAGES.copy()

    @classmethod
    def get_supported_extensions(cls) -> List[str]:
        """
        Retorna lista de extensões suportadas.

        Returns:
            Lista de extensões (incluindo o ponto)
        """
        return list(cls.EXTENSIONS.keys())

    @classmethod
    def get_language_for_extension(cls, extension: str) -> Optional[str]:
        """
        Retorna a linguagem para uma extensão específica.

        Args:
            extension: Extensão do arquivo (com ou sem ponto)

        Returns:
            Nome da linguagem ou None

        Example:
            >>> LanguageDetector.get_language_for_extension('.py')
            'python'
            >>> LanguageDetector.get_language_for_extension('js')
            'javascript'
        """
        if not extension.startswith('.'):
            extension = f'.{extension}'
        return cls.EXTENSIONS.get(extension.lower())

    @classmethod
    def filter_files_by_language(
        cls,
        file_paths: List[str],
        languages: Optional[List[str]] = None
    ) -> Dict[str, List[str]]:
        """
        Agrupa arquivos por linguagem.

        Args:
            file_paths: Lista de caminhos de arquivo
            languages: Lista de linguagens para filtrar (None = todas)

        Returns:
            Dicionário {linguagem: [arquivos]}

        Example:
            >>> files = ['a.py', 'b.js', 'c.py']
            >>> LanguageDetector.filter_files_by_language(files)
            {'python': ['a.py', 'c.py'], 'javascript': ['b.js']}
        """
        result: Dict[str, List[str]] = {}

        for file_path in file_paths:
            language = cls.detect(file_path)

            # Filtrar por linguagens se especificado
            if languages and language not in languages:
                continue

            if language not in result:
                result[language] = []
            result[language].append(file_path)

        return result

    @classmethod
    def get_language_info(cls, language: str) -> Dict[str, any]:
        """
        Retorna informações sobre uma linguagem.

        Args:
            language: Nome da linguagem

        Returns:
            Dicionário com informações da linguagem
        """
        # Extensões associadas a esta linguagem
        extensions = [
            ext for ext, lang in cls.EXTENSIONS.items()
            if lang == language.lower()
        ]

        return {
            'name': language,
            'supported': cls.is_supported(language),
            'extensions': extensions,
            'has_dependency_analysis': language in [
                'python', 'javascript', 'typescript', 'java',
                'csharp', 'go', 'ruby', 'php'
            ]
        }
