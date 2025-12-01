from abc import ABC, abstractmethod
from typing import List, Dict, Optional
import os
import shutil
import tempfile
import git
from ..utils.logger import get_logger

logger = get_logger(__name__)

class VCSProvider(ABC):
    """
    Abstract base class for Version Control System providers.
    """

    def __init__(self, token: Optional[str] = None):
        self.token = token
        self.temp_dirs = []

    @abstractmethod
    def authenticate(self) -> bool:
        """
        Verifies if the credentials are valid.
        """
        pass

    @abstractmethod
    def get_repo_url(self, repo_identifier: str) -> str:
        """
        Constructs the clone URL for a given repository identifier.
        """
        pass

    def clone_repo(self, repo_url: str, branch: Optional[str] = None) -> str:
        """
        Clones a repository to a temporary directory.

        Args:
            repo_url: The URL of the repository to clone.
            branch: Specific branch to clone.

        Returns:
            Path to the cloned repository.
        """
        try:
            temp_dir = tempfile.mkdtemp(prefix="betacode_scan_")
            self.temp_dirs.append(temp_dir)

            logger.info(f"Cloning {repo_url} into {temp_dir}")

            # Insert token into URL for authentication if needed
            # (Note: Implementations might handle this differently,
            # but usually it's https://token@host/repo.git)
            auth_url = self._inject_auth(repo_url)

            options = {}
            if branch:
                options['branch'] = branch

            git.Repo.clone_from(auth_url, temp_dir, **options)
            return temp_dir
        except Exception as e:
            logger.error(f"Failed to clone repository: {e}")
            self.cleanup()
            raise

    def cleanup(self):
        """
        Cleans up temporary directories.
        """
        for d in self.temp_dirs:
            if os.path.exists(d):
                shutil.rmtree(d, ignore_errors=True)
        self.temp_dirs = []

    def _inject_auth(self, url: str) -> str:
        """
        Injects authentication token into the URL.
        Must be implemented by subclasses if they use token-in-url auth.
        """
        return url
