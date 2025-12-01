import requests
from typing import Optional
from .base import VCSProvider
from ..utils.logger import get_logger

logger = get_logger(__name__)

class BitbucketProvider(VCSProvider):
    """
    Bitbucket integration provider.
    """

    BASE_URL = "https://api.bitbucket.org/2.0"

    def __init__(self, username: str, app_password: str):
        super().__init__(token=app_password)
        self.username = username

    def authenticate(self) -> bool:
        if not self.token or not self.username:
            return False

        try:
            response = requests.get(
                f"{self.BASE_URL}/user",
                auth=(self.username, self.token)
            )
            return response.status_code == 200
        except Exception as e:
            logger.error(f"Bitbucket authentication check failed: {e}")
            return False

    def get_repo_url(self, repo_identifier: str) -> str:
        """
        Args:
            repo_identifier: "workspace/repo_slug" format.
        """
        return f"https://bitbucket.org/{repo_identifier}.git"

    def _inject_auth(self, url: str) -> str:
        if not self.token or not self.username:
            return url
        # https://username:app_password@bitbucket.org/...
        prefix = "https://"
        if url.startswith(prefix):
            return f"{prefix}{self.username}:{self.token}@{url[len(prefix):]}"
        return url
