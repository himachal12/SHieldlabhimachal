"""
Repo Handler
Downloads GitHub repos or extracts ZIP uploads into a temp working directory
"""

import os
import shutil
import tempfile
import zipfile
from git import Repo
from app.utils.logger import get_logger

logger = get_logger("repo_handler")

# Folders we never want to scan (dependencies, build artifacts, version control internals)
EXCLUDED_DIRS = {
    'node_modules', '.git', 'venv', 'env', '__pycache__',
    'dist', 'build', '.next', 'vendor', '.venv'
}

CODE_EXTENSIONS = ('.py', '.js', '.jsx', '.ts', '.tsx', '.go')


def download_github_repo(url: str, branch: str = None) -> str:
    """
    Clone a GitHub repo into a temp directory.

    Args:
        url: GitHub repository URL
        branch: Specific branch to clone (None = default branch)

    Returns:
        Path to the cloned repo on disk

    Raises:
        Exception if clone fails (bad URL, private repo without access, etc.)
    """
    temp_dir = tempfile.mkdtemp(prefix="shieldlabs_repo_")

    try:
        logger.info(f"Cloning {url} into {temp_dir}")
        if branch:
            Repo.clone_from(url, temp_dir, branch=branch, depth=1)
        else:
            Repo.clone_from(url, temp_dir, depth=1)  # depth=1 = shallow clone, faster
        logger.info(f"Clone successful: {temp_dir}")
        return temp_dir

    except Exception as e:
        # Clean up the half-created temp dir on failure
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.error(f"Failed to clone {url}: {str(e)}")
        raise


def extract_zip(zip_path: str) -> str:
    """
    Extract an uploaded ZIP file into a temp directory.

    Args:
        zip_path: Path to the uploaded .zip file

    Returns:
        Path to the extracted folder
    """
    temp_dir = tempfile.mkdtemp(prefix="shieldlabs_zip_")

    try:
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(temp_dir)
        logger.info(f"Extracted {zip_path} into {temp_dir}")
        return temp_dir

    except zipfile.BadZipFile:
        shutil.rmtree(temp_dir, ignore_errors=True)
        logger.error(f"Invalid ZIP file: {zip_path}")
        raise ValueError("Uploaded file is not a valid ZIP archive")


def get_all_code_files(repo_path: str) -> list[str]:
    """
    Walk a directory and return all code file paths, skipping excluded dirs.

    Args:
        repo_path: Root directory to scan

    Returns:
        List of absolute file paths matching CODE_EXTENSIONS
    """
    code_files = []

    for root, dirs, files in os.walk(repo_path):
        # Modify dirs in-place to prevent os.walk from descending into excluded folders
        dirs[:] = [d for d in dirs if d not in EXCLUDED_DIRS]

        for file in files:
            if file.endswith(CODE_EXTENSIONS):
                code_files.append(os.path.join(root, file))

    logger.info(f"Found {len(code_files)} code files in {repo_path}")
    return code_files


def cleanup_temp_repo(path: str):
    """Delete a temp directory after scanning is done"""
    try:
        shutil.rmtree(path, ignore_errors=True)
        logger.info(f"Cleaned up temp dir: {path}")
    except Exception as e:
        logger.warning(f"Failed to clean up {path}: {str(e)}")