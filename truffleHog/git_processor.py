import hashlib
from functools import partial
from datetime import datetime
import shutil
from typing import List, Any, Optional

from pydantic import BaseModel

# ref: https://toolz.readthedocs.io/en/latest/index.html
from toolz.itertoolz import concat, unique
from toolz.functoolz import compose

# ref: https://gitpython.readthedocs.io/en/stable/index.html
import git

from truffleHog.utils import IO, replace, get_regexes_from_file
from truffleHog.finders import HighEntropyStringsFinder, RegexpMatchFinder


class DiffBlob(BaseModel):
    file_a: Optional[str]
    file_b: Optional[str]
    text: List[str]
    high_entropy_words: List[dict]
    regexp_matches: List[dict]


class Commit(BaseModel):
    branch: str
    commit: Any
    commit_time: datetime
    blob_diffs: List[DiffBlob]
    diff_hash: str
    next_commit: Any


class RepoProcessor:
    @staticmethod
    def process_repo(repo_url: str, max_depth: int) -> IO:
        def get_repo_from_url(repo_url):
            def fn():
                repo_path = "/tmp/repo-in-analisys"
                shutil.rmtree(repo_path, ignore_errors=True)
                return git.Repo.clone_from(repo_url, repo_path)

            return IO(fn)

        def get_remote_branches(repo):
            return repo.remotes.origin.fetch()

        def expand_branch_commit(repo, branch, max_count):
            return {
                "branch": branch.name,
                "commits": list(repo.iter_commits(branch.name, max_count=max_count)),
            }

        def add_shifted_commits(branch):
            return {**branch, "shifted_commits": get_shifted_commits(branch["commits"])}

        def get_shifted_commits(commits):
            return [git.NULL_TREE] + commits[:-1]

        def transform_to_flat_commits(branch):
            return [
                {
                    "branch": branch["branch"],
                    "commit": commit,
                    "next_commit": branch["shifted_commits"][i],
                    "diff_hash": get_diff_hash(commit, branch["shifted_commits"][i]),
                    "commit_time": datetime.fromtimestamp(
                        commit.committed_date
                    ).strftime("%Y-%m-%d %H:%M:%S"),
                }
                for i, commit in enumerate(branch["commits"])
            ]

        def get_diff_hash(a, b):
            return hashlib.md5((str(a) + str(b)).encode("utf-8")).hexdigest()

        def add_blobs_diffs(commit):
            return {
                **commit,
                "blob_diffs": compose(
                    list,
                    partial(map, to_diff_blob_struct),
                    partial(map, expand_blob_lines),
                    partial(filter, not_binary_blob),
                    get_diff_blobs,
                )(commit),
            }

        def expand_blob_lines(blob):
            return {**blob, "text": blob["text"].split("\n")}

        def not_binary_blob(blobs_diff):
            return not blobs_diff["text"].startswith("Binary files")

        def get_diff_blobs(commit):
            return [
                {
                    "file_a": blob.a_path,
                    "file_b": blob.b_path,
                    "text": blob.diff.decode("utf-8", errors="replace"),
                }
                for blob in commit["commit"].diff(
                    commit["next_commit"], create_patch=True
                )
            ]

        def to_commit_struct(commit_dict):
            return Commit(**commit_dict)

        def to_diff_blob_struct(blob_dict):
            return DiffBlob(**blob_dict, high_entropy_words=[], regexp_matches=[])

        # -- main --

        def fn(repo, max_depth=max_depth):
            return compose(
                list,
                partial(unique, key=lambda x: x.diff_hash),
                partial(map, compose(to_commit_struct, add_blobs_diffs)),
                concat,
                partial(
                    map,
                    compose(
                        transform_to_flat_commits,
                        add_shifted_commits,
                        partial(expand_branch_commit, repo, max_count=max_depth),
                    ),
                ),
                get_remote_branches,
            )

        return get_repo_from_url(repo_url).map(lambda repo: fn(repo, max_depth)(repo))


def update_blob_field(commits, field, update_fn) -> List[Commit]:
    def get_new_blob_diffs(update_fn, commit):
        return [replace(blob, field, update_fn(blob)) for blob in commit.blob_diffs]

    def update_commit_blobs(update_fn, commit):
        return replace(commit, "blob_diffs", get_new_blob_diffs(update_fn, commit))

    return [update_commit_blobs(update_fn, commit) for commit in commits]


def find_high_entropy_strings(commits) -> List[Commit]:
    return update_blob_field(
        commits, "high_entropy_words", HighEntropyStringsFinder.apply
    )


def find_matching_regexps(regexes_objects, commits) -> List[Commit]:
    return update_blob_field(
        commits, "regexp_matches", partial(RegexpMatchFinder.apply, regexes_objects)
    )


def scan_repo(repo_url: str, use_entropy=True, use_regexps=True, max_depth=1000000):
    # impure
    commits = RepoProcessor.process_repo(
        repo_url, max_depth=max_depth
    ).unsafePerformIO()
    if use_entropy:
        commits = find_high_entropy_strings(commits)
    if use_regexps:
        regexes_objects = get_regexes_from_file().unsafePerformIO()
        commits = find_matching_regexps(regexes_objects, commits)

    return commits


# run with:
#   python -m truffleHog.git_processor

if __name__ == "__main__":
    result = scan_repo("https://github.com/sortigoza/truffleHog.git")
    print(result)
