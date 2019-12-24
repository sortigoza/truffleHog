import argparse
import os
import re
import json
from truffleHog.git_processor import scan_repo
from truffleHog.file_processor import scan_file, File

from truffleHog.presenters import simple_presenter, json_presenter


def get_args():
    parser = argparse.ArgumentParser(
        description="Find secrets hidden in the depths of git."
    )
    parser.add_argument(
        "--regex",
        dest="do_regex",
        action="store_true",
        help="Enable high signal regex checks",
        default=False,
    )
    parser.add_argument(
        "--entropy", dest="do_entropy", help="Enable entropy checks", default=True
    )
    # TODO: implement this later
    # parser.add_argument(
    #     "--since_commit",
    #     dest="since_commit",
    #     help="Only scan from a given commit hash",
    #     default=None,
    # )
    parser.add_argument(
        "--max_depth",
        dest="max_depth",
        help="The max commit depth to go back when searching for secrets",
        default=1000000,
    )
    parser.add_argument(
        "--json", dest="output_json", action="store_true", help="Output in JSON"
    )
    # TODO: implement these later
    # parser.add_argument(
    #     "--rules",
    #     dest="rules",
    #     help="Ignore default regexes and source from json list file",
    #     default={},
    # )
    # parser.add_argument(
    #     "-i",
    #     "--include_paths",
    #     type=argparse.FileType("r"),
    #     metavar="INCLUDE_PATHS_FILE",
    #     help="File with regular expressions (one per line), at least one of which must match a Git "
    #     'object path in order for it to be scanned; lines starting with "#" are treated as '
    #     "comments and are ignored. If empty or not provided (default), all Git object paths "
    #     "are included unless otherwise excluded via the --exclude_paths option.",
    # )
    # parser.add_argument(
    #     "-x",
    #     "--exclude_paths",
    #     type=argparse.FileType("r"),
    #     metavar="EXCLUDE_PATHS_FILE",
    #     help="File with regular expressions (one per line), none of which may match a Git object "
    #     'path in order for it to be scanned; lines starting with "#" are treated as comments '
    #     "and are ignored. If empty or not provided (default), no Git object paths are "
    #     "excluded unless  effectively excluded via the --include_paths option.",
    # )
    parser.add_argument(
        "files_or_git_url",
        nargs="+",
        type=str,
        help="URL or list of files for secret searching",
    )

    return parser.parse_args()


def is_remote_repo(item: str):
    # from https://stackoverflow.com/questions/2514859/regular-expression-for-git-repository
    return re.match(
        r"((git|ssh|http(s)?)|(git@[\w\.]+))(:(//)?)([\w\.@\:/\-~]+)(\.git)(/)?", item
    )


def is_local_file(item: str):
    return re.match(r"^[\w\-\. /]+$", item)


def _is_binary_file(file_path: str):
    textchars = bytearray({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7F})

    def is_binary_string(bytes):
        return bool(bytes.translate(None, textchars))

    return is_binary_string(open(file_path, "rb").read(1024))


def proces_local_file(args, file_path):
    if not os.path.isfile(file_path):
        return File(
            path=file_path,
            mime_type="not-a-file",
            text=[],
            high_entropy_words=[],
            regexp_matches=[],
        )

    if _is_binary_file(file_path):
        return File(
            path=file_path,
            mime_type="binary-file",
            text=[],
            high_entropy_words=[],
            regexp_matches=[],
        )

    scanned_file = scan_file(file_path)

    if args.output_json:
        # TODO: implement json presenter
        print(json.dumps(dict(scanned_file)))
    else:
        # TODO: implement simple presenter
        print(scanned_file)


def proces_remote_repo(args, repo_url):
    commits = scan_repo(repo_url, max_depth=args.max_depth)

    if args.output_json:
        json_presenter(commits)
    else:
        simple_presenter(commits)


def main():
    args = get_args()
    for item in args.files_or_git_url:
        if is_remote_repo(item):
            proces_remote_repo(args, item)
        elif is_local_file(item):
            proces_local_file(args, item)
        else:
            raise Exception("input not supported")


if __name__ == "__main__":
    main()
