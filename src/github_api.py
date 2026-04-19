"""OwlGuard GitHub API — create PRs, post comments, manage branches."""
import json
import time
import hashlib
import hmac
import httpx
from dataclasses import dataclass


@dataclass
class GitHubRepo:
    owner: str
    name: str
    full_name: str
    clone_url: str
    default_branch: str


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Verify GitHub webhook signature (HMAC-SHA256)."""
    if not signature.startswith("sha256="):
        return False
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return hmac.compare_digest(f"sha256={expected}", signature)


class GitHubClient:
    """GitHub API client for OwlGuard."""

    def __init__(self, token: str):
        self.token = token
        self.base = "https://api.github.com"
        self.headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "OwlGuard/0.1",
        }

    def get_repo(self, owner: str, name: str) -> GitHubRepo:
        resp = httpx.get(f"{self.base}/repos/{owner}/{name}", headers=self.headers)
        resp.raise_for_status()
        data = resp.json()
        return GitHubRepo(
            owner=owner, name=name,
            full_name=data["full_name"],
            clone_url=data["clone_url"],
            default_branch=data.get("default_branch", "main"),
        )

    def create_branch(self, owner: str, name: str, branch: str, from_sha: str) -> bool:
        resp = httpx.post(
            f"{self.base}/repos/{owner}/{name}/git/refs",
            headers=self.headers,
            json={"ref": f"refs/heads/{branch}", "sha": from_sha},
        )
        return resp.status_code == 201

    def get_default_branch_sha(self, owner: str, name: str) -> str:
        resp = httpx.get(f"{self.base}/repos/{owner}/{name}/git/ref/heads/main", headers=self.headers)
        if resp.status_code != 200:
            resp = httpx.get(f"{self.base}/repos/{owner}/{name}/git/ref/heads/master", headers=self.headers)
        resp.raise_for_status()
        return resp.json()["object"]["sha"]

    def update_file(self, owner: str, name: str, path: str, content: str,
                    message: str, branch: str, sha: str) -> bool:
        import base64
        resp = httpx.put(
            f"{self.base}/repos/{owner}/{name}/contents/{path}",
            headers=self.headers,
            json={
                "message": message,
                "content": base64.b64encode(content.encode()).decode(),
                "sha": sha,
                "branch": branch,
            },
        )
        return resp.status_code == 200

    def create_pr(self, owner: str, name: str, title: str, body: str,
                  head: str, base: str = "main") -> dict:
        resp = httpx.post(
            f"{self.base}/repos/{owner}/{name}/pulls",
            headers=self.headers,
            json={"title": title, "body": body, "head": head, "base": base},
        )
        resp.raise_for_status()
        return resp.json()

    def comment_on_pr(self, owner: str, name: str, pr_number: int, body: str) -> bool:
        resp = httpx.post(
            f"{self.base}/repos/{owner}/{name}/issues/{pr_number}/comments",
            headers=self.headers,
            json={"body": body},
        )
        return resp.status_code == 201

    def comment_on_commit(self, owner: str, name: str, sha: str, body: str) -> bool:
        resp = httpx.post(
            f"{self.base}/repos/{owner}/{name}/commits/{sha}/comments",
            headers=self.headers,
            json={"body": body},
        )
        return resp.status_code == 201
