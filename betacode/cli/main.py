import click
import os
import sys
from betacode.core.engine import BetaCodeEngine
from betacode.integrations import GitHubProvider, BitbucketProvider, AzureDevOpsProvider
from betacode.utils.logger import get_logger

logger = get_logger(__name__)

@click.group()
def cli():
    """BetaCode - Professional SAST Tool"""
    pass

@cli.command()
@click.argument('path', type=click.Path(exists=True))
@click.option('--format', '-f', multiple=True, default=['json'], help='Output format (json, html, sarif)')
@click.option('--output', '-o', help='Output file path')
def analyze(path, format, output):
    """Analyze a local file or directory."""
    engine = BetaCodeEngine()
    try:
        results = engine.analyze(path)

        # Determine output strategy
        if output:
            import json

            # Simple Output Handler
            if 'html' in format:
                _generate_html_report(results, output)
            elif 'sarif' in format:
                _generate_sarif_report(results, output)
            else:
                # Default to JSON
                with open(output, 'w') as f:
                    data = {
                        "findings": [
                            {
                                "id": f.id,
                                "rule_id": f.rule_id,
                                "severity": f.severity.name,
                                "file": f.file,
                                "line": f.line,
                                "message": f.message,
                                "code": f.code_snippet
                            } for f in results.findings
                        ],
                        "metrics": results.metrics
                    }
                    json.dump(data, f, indent=2)

            click.echo(f"Results saved to {output}")

        click.echo(f"Analysis complete. Found {results.total_findings} findings.")
        for finding in results.findings:
            click.echo(f"[{finding.severity.name}] {finding.message} ({finding.file}:{finding.line})")

    except Exception as e:
        click.echo(f"Error during analysis: {e}", err=True)
        sys.exit(1)

@cli.command(name='import')
@click.argument('provider', type=click.Choice(['github', 'bitbucket', 'azure'], case_sensitive=False))
@click.argument('repo_identifier')
@click.option('--token', envvar='BETACODE_TOKEN', help='Access token for the provider')
@click.option('--username', help='Username (required for Bitbucket)')
@click.option('--org', help='Organization (required for Azure DevOps)')
def import_and_analyze(provider, repo_identifier, token, username, org):
    """
    Import and analyze a repository from a VCS provider.

    REPO_IDENTIFIER examples:
    - github: owner/repo
    - bitbucket: workspace/repo_slug
    - azure: project/repo or repo (if unique)
    """
    if not token:
        click.echo("Error: Token is required. Use --token or set BETACODE_TOKEN env var.", err=True)
        sys.exit(1)

    client = None
    if provider == 'github':
        client = GitHubProvider(token=token)
    elif provider == 'bitbucket':
        if not username:
            click.echo("Error: --username is required for Bitbucket.", err=True)
            sys.exit(1)
        client = BitbucketProvider(username=username, app_password=token)
    elif provider == 'azure':
        if not org:
            click.echo("Error: --org is required for Azure DevOps.", err=True)
            sys.exit(1)
        client = AzureDevOpsProvider(organization=org, token=token)

    if not client.authenticate():
        click.echo("Authentication failed. Please check your credentials.", err=True)
        sys.exit(1)

    repo_url = client.get_repo_url(repo_identifier)
    click.echo(f"Cloning {repo_url}...")

    try:
        local_path = client.clone_repo(repo_url)
        click.echo(f"Repository cloned to {local_path}")

        click.echo("Starting analysis...")
        engine = BetaCodeEngine()
        results = engine.analyze(local_path)

        click.echo(f"Analysis complete. Found {results.total_findings} findings.")
        for finding in results.findings:
            click.echo(f"[{finding.severity.name}] {finding.message} ({finding.file.replace(local_path, '')}:{finding.line})")

    except Exception as e:
        click.echo(f"Error: {e}", err=True)
    finally:
        if client:
            client.cleanup()

def _generate_html_report(results, output_path):
    """Generates a simple HTML report."""
    html_content = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>BetaCode Scan Report</title>
        <style>
            body {{ font-family: Arial, sans-serif; margin: 20px; }}
            h1 {{ color: #333; }}
            .summary {{ background: #f4f4f4; padding: 15px; border-radius: 5px; }}
            .finding {{ border: 1px solid #ddd; margin-bottom: 10px; padding: 10px; border-radius: 5px; }}
            .CRITICAL {{ border-left: 5px solid #d9534f; }}
            .HIGH {{ border-left: 5px solid #f0ad4e; }}
            .MEDIUM {{ border-left: 5px solid #5bc0de; }}
            .LOW {{ border-left: 5px solid #5cb85c; }}
            .code {{ background: #eee; padding: 5px; font-family: monospace; display: block; white-space: pre-wrap; }}
        </style>
    </head>
    <body>
        <h1>BetaCode Analysis Report</h1>
        <div class="summary">
            <p>Target: {results.target}</p>
            <p>Total Findings: {results.total_findings}</p>
            <p>Risk Score: {results.metrics.get('risk_score', 0)}</p>
        </div>
        <h2>Findings</h2>
    """

    for finding in results.findings:
        html_content += f"""
        <div class="finding {finding.severity.name}">
            <h3>[{finding.severity.name}] {finding.message}</h3>
            <p><strong>Rule:</strong> {finding.rule_id} | <strong>CWE:</strong> {finding.cwe}</p>
            <p><strong>File:</strong> {finding.file}:{finding.line}</p>
            <code class="code">{finding.code_snippet}</code>
            <p><strong>Remediation:</strong> {finding.remediations[0] if finding.remediations else 'N/A'}</p>
        </div>
        """

    html_content += """
    </body>
    </html>
    """

    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)

def _generate_sarif_report(results, output_path):
    """Generates a SARIF report."""
    import json

    runs = [{
        "tool": {
            "driver": {
                "name": "BetaCode",
                "version": "1.0.0",
                "rules": []
            }
        },
        "results": []
    }]

    rules_map = {}

    for finding in results.findings:
        if finding.rule_id not in rules_map:
            rule_idx = len(rules_map)
            rules_map[finding.rule_id] = rule_idx
            runs[0]["tool"]["driver"]["rules"].append({
                "id": finding.rule_id,
                "shortDescription": {"text": finding.message},
                "help": {"text": "\n".join(finding.remediations) if finding.remediations else ""}
            })

        runs[0]["results"].append({
            "ruleId": finding.rule_id,
            "level": "error" if finding.severity.name in ['CRITICAL', 'HIGH'] else "warning",
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.file},
                    "region": {
                        "startLine": finding.line,
                        "startColumn": finding.column
                    }
                }
            }]
        })

    with open(output_path, 'w', encoding='utf-8') as f:
        json.dump({"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0-rtm.5.json", "runs": runs}, f, indent=2)

if __name__ == '__main__':
    cli()
