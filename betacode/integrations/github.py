import requests
from typing import Optional
from .base import VCSProvider
from ..utils.logger import get_logger

logger = get_logger(__name__)

class GitHubProvider(VCSProvider):
    """
    GitHub integration provider.
    """

    BASE_URL = "https://api.github.com"

    def authenticate(self) -> bool:
        if not self.token:
            return False

        headers = {
            "Authorization": f"Bearer {self.token}",
            "Accept": "application/vnd.github.v3+json"
        }
        try:
            response = requests.get(f"{self.BASE_URL}/user", headers=headers)
            return response.status_code == 200
        except Exception as e:
            logger.error(f"GitHub authentication check failed: {e}")
            return False

    def get_repo_url(self, repo_identifier: str) -> str:
        """
        Args:
            repo_identifier: "owner/repo" format.
        """
        return f"https://github.com/{repo_identifier}.git"

    def _inject_auth(self, url: str) -> str:
        if not self.token:
            return url
        # https://x-access-token:<token>@github.com/owner/repo.git
        prefix = "https://"
        if url.startswith(prefix):
            return f"{prefix}x-access-token:{self.token}@{url[len(prefix):]}"
        return url
