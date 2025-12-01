import requests
import base64
from typing import Optional
from .base import VCSProvider
from ..utils.logger import get_logger

logger = get_logger(__name__)

class AzureDevOpsProvider(VCSProvider):
    """
    Azure DevOps integration provider.
    """

    def __init__(self, organization: str, token: str):
        super().__init__(token=token)
        self.organization = organization
        self.base_url = f"https://dev.azure.com/{organization}"

    def authenticate(self) -> bool:
        if not self.token:
            return False

        # Encode PAT for Basic Auth
        auth_str = f":{self.token}"
        b64_auth = base64.b64encode(auth_str.encode()).decode()
        headers = {
            "Authorization": f"Basic {b64_auth}"
        }

        try:
            # Try to list projects to verify access
            response = requests.get(
                f"{self.base_url}/_apis/projects?api-version=7.0",
                headers=headers
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Azure DevOps authentication check failed: {e}")
            return False

    def get_repo_url(self, repo_identifier: str) -> str:
        """
        Args:
            repo_identifier: "project/repo" format or just "repo" if unique in org (less common).
            Usually in Azure DevOps it's Organization/Project/_git/Repo
        """
        # Assuming identifier is "project/repo"
        parts = repo_identifier.split('/')
        if len(parts) == 2:
            project, repo = parts
            return f"{self.base_url}/{project}/_git/{repo}"
        else:
             # Fallback or assume simple structure
            return f"{self.base_url}/_git/{repo_identifier}"

    def _inject_auth(self, url: str) -> str:
        if not self.token:
            return url

        # Azure DevOps PAT works with empty username
        # https://pat@dev.azure.com/...
        prefix = "https://"
        if url.startswith(prefix):
            # Using token as password with empty username is standard for basic auth in git url
            # But commonly: https://user:token@... or https://token@...
            # For ADO, putting the token usually works.
            return f"{prefix}{self.token}@{url[len(prefix):]}"
        return url
