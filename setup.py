"""
BetaCode - Setup Script

Instalação:
    pip install -e .

Desenvolvimento:
    pip install -e ".[dev]"
"""

from setuptools import setup, find_packages
from pathlib import Path

# Ler README
this_directory = Path(__file__).parent
long_description = (this_directory / "README.md").read_text(encoding='utf-8') \
    if (this_directory / "README.md").exists() else ""

# Ler requirements
requirements = []
requirements_file = this_directory / "requirements.txt"
if requirements_file.exists():
    with open(requirements_file, 'r', encoding='utf-8') as f:
        requirements = [
            line.strip() for line in f
            if line.strip() and not line.startswith('#')
        ]

setup(
    name="betacode",
    version="1.0.0",
    author="BetaCode Team",
    author_email="betacode@example.com",
    description="Ferramenta profissional de análise estática de código (SAST)",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/GhostN3xus/BetaCode",
    project_urls={
        "Bug Tracker": "https://github.com/GhostN3xus/BetaCode/issues",
        "Documentation": "https://github.com/GhostN3xus/BetaCode/wiki",
        "Source Code": "https://github.com/GhostN3xus/BetaCode",
    },
    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,
    package_data={
        'betacode': [
            'rules/**/*.yaml',
            'rules/**/*.yml',
            'config/**/*.yaml',
            'config/**/*.yml',
        ],
    },
    classifiers=[
        "Development Status :: 4 - Beta",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Security",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.11",
    install_requires=requirements,
    extras_require={
        "dev": [
            "pytest>=7.4.3",
            "pytest-cov>=4.1.0",
            "pytest-mock>=3.12.0",
            "black>=23.12.1",
            "flake8>=7.0.0",
            "mypy>=1.8.0",
            "isort>=5.13.2",
            "pylint>=3.0.3",
        ],
    },
    entry_points={
        "console_scripts": [
            "betacode=betacode.cli.main:cli",
        ],
    },
    keywords=[
        "sast", "security", "static-analysis", "code-analysis",
        "vulnerability-scanner", "security-testing", "devsecops"
    ],
    zip_safe=False,
)
