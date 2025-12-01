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
@click.option('--format', '-f', multiple=True, default=['json'], help='Output format (json)')
@click.option('--output', '-o', help='Output file path')
def analyze(path, format, output):
    """Analyze a local file or directory."""
    engine = BetaCodeEngine()
    try:
        results = engine.analyze(path)

        # Determine output strategy
        if output:
            import json
            # Basic JSON dump if output is specified, handling just one format for simplicity in this iteration
            # In a full implementation, we would use a Reporter class to handle multiple formats
            with open(output, 'w') as f:
                if 'json' in format:
                    # Convert results to dict (simplified)
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

if __name__ == '__main__':
    cli()
