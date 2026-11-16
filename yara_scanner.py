#!/usr/bin/env python3
# vim: sw=4:ts=4:et:cc=120
__version__ = "3.2.1"
__doc__ = """
Yara Scanner v2
============

A wrapper around the yara library for Python. ::

    scanner = YaraScanner()
    # start tracking this yara file
    scanner.track_yara_file('/path/to/yara_file.yar')
    scanner.load_rules()
    scanner.scan('/path/to/file/to/scan')

    # check to see if your yara file changed
    if scanner.check_rules():
        scanner.load_rules()

    # track an entire directory of yara files
    scanner.track_yara_dir('/path/to/directory')
    scanner.load_rules()
    # did any of the yara files in this directory change?
    if scanner.check_rules():
        scanner.load_rules()

    # track a git repository of yara rules
    scanner.track_yara_repo('/path/to/git_repo')
    scanner.load_rules()
    # this only returns True if a new commit was added since the last check
    if scanner.check_rules():
        scanner.load_rules()

"""

import csv
import functools
import io
import itertools
import json
import logging
import os
import os.path
import re
import shutil
import stat
import sys
import time

from dataclasses import dataclass, field
from operator import itemgetter
import hashlib
import tempfile
from subprocess import PIPE, Popen
from typing import Dict, Iterable, List, Optional

import plyara, plyara.utils
import progress.bar
import yara


@dataclass
class IncludedSource:
    """A file an include statement pulled in while a rule file compiled."""

    #: the file name as the include statement gives it
    name: str
    #: the path it resolved to
    path: str
    #: the text compiled in place of the include statement ("" when the file could not be read)
    source: str
    #: why the file could not be read, or None
    error: Optional[str] = None


@dataclass
class CompiledSource:
    """A rule file YaraScanner.compile_and_load_rules read, and what compiling it on its own gave."""

    path: str
    #: the namespace its rules are loaded into
    namespace: str
    #: the text read from path, which is what was compiled ("" when it could not be read)
    source: str
    #: every include compiling it pulled in, nested ones too, in the order yara asked for them
    includes: List[IncludedSource] = field(default_factory=list)
    #: why it could not be read or did not compile on its own, or None. A file with an error is left
    #: out of the rules
    error: Optional[str] = None
    #: the compiler's warnings
    warnings: List[str] = field(default_factory=list)
    #: the identifiers of the rules it defines, those of its includes too
    rules: List[str] = field(default_factory=list)


class RulesNotLoadedError(Exception):
    """Raised when a call is made to scan before any rules have been loaded."""
    pass


class IncludeRefusedError(Exception):
    """Raised for a file the include boundary does not let the compile read. Its message is the
    error recorded for the file; it never depends on anything outside the boundary."""
    pass


def _is_inside(path: str, root: str) -> bool:
    """True when path is below root. Both are absolute and normalized; nothing is opened."""
    return path.startswith(root.rstrip(os.sep) + os.sep)


def open_include(dir_name: str, requested_filename: str, boundary: str, tracked_dirs: Iterable[str] = ()):
    """Opens the file an include statement in a file of dir_name names, when it is a regular file
    inside the directory boundary that is reached through no symbolic link. Anything else raises
    :class:`IncludeRefusedError`, before it is opened.

    An absolute name and a name that leaves the boundary are refused from the text of the path
    alone, so the refusal is the same whether or not the file exists. The filesystem is looked at
    only below the boundary, one path component at a time, and a symbolic link is refused where it
    is found, without looking at what it points to. The one exception is a link that is one of
    tracked_dirs, the directories inside the boundary that rules are tracked in: whoever tracked
    them chose them, so a rule set linked into a signature directory is followed into, but nothing
    below it is. The path opened is the normalized one that was checked. A file missing inside the
    boundary raises FileNotFoundError, as it always has."""
    if os.path.isabs(requested_filename):
        raise IncludeRefusedError("include refused: an absolute path is not allowed")

    root = os.path.abspath(boundary)
    target = os.path.normpath(os.path.join(os.path.abspath(dir_name), requested_filename))
    if target == root:
        raise IncludeRefusedError("include refused: not a regular file")

    if not _is_inside(target, root):
        raise IncludeRefusedError("include refused: the path leaves the include boundary")

    followed = {os.path.abspath(_) for _ in tracked_dirs}
    current = root
    for part in os.path.relpath(target, root).split(os.sep):
        current = os.path.join(current, part)
        mode = os.lstat(current).st_mode
        if stat.S_ISLNK(mode):
            if current not in followed:
                raise IncludeRefusedError("include refused: the path goes through a symbolic link")

            mode = os.stat(current).st_mode

    if not stat.S_ISREG(mode):
        raise IncludeRefusedError("include refused: not a regular file")

    return open(target, "r")


def rule_file_refusal(file_path: str, boundary: str, tracked_dirs: Iterable[str] = ()) -> Optional[str]:
    """Returns why a rule file found by listing a directory is not read, or None when it can be.
    The file can be a symbolic link, or be reached through one, as long as what it resolves to is
    inside the directory boundary, or inside what one of tracked_dirs resolves to (a tracked
    directory can be a link out of the boundary, see :func:`open_include`). Whether the target of a
    link out of the boundary exists makes no difference to the answer."""
    resolved = os.path.realpath(file_path)
    if _is_inside(resolved, os.path.realpath(boundary)):
        return None

    # resolved one at a time: a file of the default layout never gets here, and the caller passes
    # the file's own directory first
    for dir_path in tracked_dirs:
        if _is_inside(resolved, os.path.realpath(dir_path)):
            return None

    return "rule file refused: it resolves to a path outside the include boundary"


# keys to the JSON dicts you get back from YaraScanner.scan_results
RESULT_KEY_TARGET = "target"
RESULT_KEY_META = "meta"
RESULT_KEY_NAMESPACE = "namespace"
RESULT_KEY_COMMIT = "commit"
RESULT_KEY_RULE = "rule"
RESULT_KEY_STRINGS = "strings"
RESULT_KEY_TAGS = "tags"
ALL_RESULT_KEYS = [
    RESULT_KEY_TARGET,
    RESULT_KEY_META,
    RESULT_KEY_NAMESPACE,
    RESULT_KEY_COMMIT,
    RESULT_KEY_RULE,
    RESULT_KEY_STRINGS,
    RESULT_KEY_TAGS,
]

DEFAULT_YARA_EXTERNALS = {
    "filename": "",
    "filepath": "",
    "extension": "",
    "filetype": "",
}

yara.set_config(max_strings_per_rule=30720)
log = logging.getLogger("yara-scanner")


def get_current_repo_commit(repo_dir):
    """Utility function to return the current commit hash for a given repo directory.  Returns None on failure."""
    p = Popen(
        ["git", "-C", repo_dir, "log", "-n", "1", "--format=oneline"], stdout=PIPE, stderr=PIPE, universal_newlines=True
    )
    commit, stderr = p.communicate()
    p.wait()

    if len(stderr.strip()) > 0:
        log.error("git reported an error: {}".format(stderr.strip()))

    if len(commit) < 40:
        log.error("got {} for stdout with git log".format(commit.strip()))
        return None

    return commit[0:40]


def _getmtime(path):
    """The modification time of a file, or None for one that is not there (a link to nothing.)"""
    try:
        return os.path.getmtime(path)
    except OSError:
        return None


def get_rules_md5(namespaces: Dict[str, List[str]]) -> str:
    """Combine all of the rule files and hash. We can then store the compiled
    rules to disk and reload on a later run if nothing has changed"""
    m = hashlib.md5()
    for namespace in sorted(namespaces):
        for path in sorted(namespaces[namespace]):
            with open(path, "rb") as fp:
                while True:
                    chunk = fp.read(io.DEFAULT_BUFFER_SIZE)
                    if chunk == b"":
                        break

                    m.update(chunk)

    return m.hexdigest()


class YaraJSONEncoder(json.JSONEncoder):
    def default(self, o):
        if isinstance(o, bytes):
            return o.decode("utf-8", errors="backslashreplace")

        return json.JSONEncoder.default(self, o)


class YaraScanner(object):
    """
    The primary object used for scanning files and data with yara rules."""

    def __init__(
        self,
        signature_dir=None,
        thread_count=None,
        test_mode=False,
        auto_compile_rules=False,
        auto_compiled_rules_dir=None,
        default_timeout=5,
        git_repo_dirs=None,
        allow_includes_outside=False,
    ):
        """
        Creates a new YaraScanner object.

        :param signature_dir: A directory that contains one directory per set
        of yara rules. Each subdirectory will get loaded into its own namespace
        (named after the path to the directory.) This is for convenience. Also
        see :func:`YaraScanner.track_yara_file`,
        :func:`YaraScanner.track_yara_dir`, and
        :func:`YaraScanner.track_yara_repo`.

        :param git_repo_dirs: The subdirectories of signature_dir that are part
        of a git repository. These are tracked with
        :func:`YaraScanner.track_yara_repository` (only new commits trigger a
        rule reload, and matches report the commit hash.) Every other
        subdirectory is tracked with :func:`YaraScanner.track_yara_dir`. Entries
        can be the name of the subdirectory or a path to it. 

        :param compile_rules: Set to True to save and load compiled rules using
        the compiled_rules_dir. Defaults to False.

        :para compiled_rules_dir: A path to a directory to read/write compiled rules.
        If this is left as None then the system temporary directory is used.

        :param allow_includes_outside: By default an include statement can
        only read a regular file inside the *include boundary* of the rule file
        it is in, reached through no symbolic link, and a rule file found by
        listing a directory is read only if it resolves to a path inside that
        boundary. The boundary is the tracked directory, the directory of a
        file tracked on its own, or signature_dir for the directories found in
        it; the track functions take an include_boundary to use another. Set
        this to True to read whatever an include names and whatever a rule
        file links to, as versions before 3.2.0 did. Only do that when
        everyone who can write a rule is trusted with every file the process
        can read.

        :type signature_dir: str or None
        :type git_repo_dirs: list[str] or None
        :type allow_includes_outside: bool


        """
        self.rules = None
        self._scan_results = []

        # what the last compile_and_load_rules() compiled; empty when the rules came from a compiled file
        self.compiled_sources: List[CompiledSource] = []
        # why the last compile_and_load_rules() could not compile the files together, or None
        self.compile_error: Optional[str] = None

        # we can pass in a list of "blacklisted" rules
        # this is a list of rule NAMES that are essentially ignored in the scan results (not output)
        self._blacklisted_rules = set()

        # we keep track of when the rules change and (optionally) automatically re-load the rules
        self.tracked_files = {}  # key = file_path, value = last modification time
        self.tracked_dirs = {}  # key = dir_path, value = {} (key = file_path, value = last mtime)
        self.tracked_repos = {}  # key = dir_path, value = current git commit
        self.tracked_compiled_path = None
        self.tracked_compiled_lastmtime = None

        # an include may only read inside the boundary of the namespace its rule file is in
        self.allow_includes_outside = allow_includes_outside
        # key = namespace (the tracked file_path or dir_path), value = the directory its includes
        # must stay inside. A namespace with no entry is bounded by its own directory.
        self.include_boundaries = {}

        # both parameters to this function are for backwards compatibility
        if thread_count is not None:
            # TODO use warnings
            log.warning("thread_count is no longer used in YaraScanner.__init__")

        # we are reading/writing compiled rules?
        self.auto_compile_rules = auto_compile_rules

        # where to save/load compiled rules from
        self.auto_compiled_rules_dir = auto_compiled_rules_dir
        if not self.auto_compiled_rules_dir:
            self.auto_compiled_rules_dir = os.path.join(tempfile.gettempdir(), "compiled_rules")

        # if a "signature directory" is specific then we automatically start tracking rules
        if signature_dir is not None and os.path.isdir(signature_dir):
            # which of these directories did the caller say are part of a git repository?
            git_repo_paths = {self._resolve_signature_subdir(signature_dir, _) for _ in (git_repo_dirs or [])}
            tracked_repo_paths = set()

            for dir_path in os.listdir(signature_dir):
                dir_path = os.path.join(signature_dir, dir_path)
                if not os.path.isdir(dir_path):
                    continue

                resolved_path = os.path.realpath(dir_path)
                if resolved_path in git_repo_paths:
                    tracked_repo_paths.add(resolved_path)
                    self.track_yara_repository(dir_path, include_boundary=signature_dir)
                else:
                    # a rule set can include a file of the set next to it
                    self.track_yara_dir(dir_path, include_boundary=signature_dir)

            for missing_path in git_repo_paths - tracked_repo_paths:
                log.error("{} is not a directory in signature directory {}".format(missing_path, signature_dir))

        elif git_repo_dirs:
            log.error("git_repo_dirs was specified without a valid signature_dir: it has no effect")

        # the default amount of time (in seconds) a yara scan is allowed to take before it fails
        self.default_timeout = default_timeout

    @property
    def scan_results(self):
        """Returns the scan results of the most recent scan.

        This function returns a list of dict with the following format ::

            {
                'target': str,
                'meta': dict,
                'namespace': str,
                'commit': str or None,
                'rule': str,
                'strings': list,
                'tags': list,
            }

        **target** is the target of the scane. In the case of file scans then target will be the path to the file that was scanned. In the case of data (raw binary) scans, this will be an empty string.

        **meta** is the dict of meta directives of the matching rule.

        **namespace** is the namespace the rule is in. In the case of repo and directory tracking, this will be the path of the directory. Otherwise it has a hard coded value of DEFAULT. *Setting the namespace to the path of the directory allows yara rules with duplicate names in different directories to be added to the same yara context.*

        **commit** is the git commit hash the matching rule's source was tracked at, when the rule came from a git repository (see :func:`YaraScanner.track_yara_repository`). It is ``None`` for rules loaded from a directory, single file, or pre-compiled rules.

        **rule** is the name of the matching yara rule.

        **strings** is a list of tuples representing the individual string matches in the following format. ::

            (position, string_name, content)

        where **position** is the byte position of the match, **string_name** is the name of the yara string that matched, and **content** is the binary content it matched.

        **tags** is a list of tags contained in the matching rule.
        """
        return self._scan_results

    @scan_results.setter
    def scan_results(self, value):
        self._scan_results = value

    @property
    def blacklist(self):
        """The list of yara rules configured as blacklisted. Rules that are blacklisted are not compiled and used."""
        return list(self._blacklisted_rules)

    @blacklist.setter
    def blacklist(self, value):
        assert isinstance(value, list)
        self._blacklisted_rules = set(value)

    def blacklist_rule(self, rule_name):
        """Adds the given rule to the list of rules that are blacklisted. See :func:`YaraScanner.blacklist`."""
        self._blacklisted_rules.add(rule_name)

    @property
    def json(self):
        """Returns the current scan results as a JSON formatted string."""
        return json.dumps(self.scan_results, indent=4, sort_keys=True, cls=YaraJSONEncoder)

    @functools.lru_cache()
    def git_available(self):
        """Returns True if git is available on the system, False otherwise."""
        return shutil.which("git")

    @staticmethod
    def _resolve_signature_subdir(signature_dir, dir_path):
        """Returns the resolved path of a subdirectory of the given signature directory.
        dir_path can be the name of the subdirectory or a path to it."""
        if not os.path.isabs(dir_path):
            dir_path = os.path.join(signature_dir, dir_path)

        return os.path.realpath(dir_path)

    def track_compiled_yara_file(self, file_path):
        """Tracks the given file that contains compiled yara rules."""
        self.tracked_compiled_path = file_path
        if os.path.exists(file_path):
            self.tracked_compiled_lastmtime = os.path.getmtime(file_path)

    def get_include_boundary(self, namespace):
        """Returns the directory the includes of the rule files in the given namespace must stay
        inside: the one it was tracked with, or else the tracked directory itself (the directory of
        a file tracked on its own.)"""
        boundary = self.include_boundaries.get(namespace)
        if boundary is not None:
            return boundary

        if namespace in self.tracked_files:
            return os.path.dirname(namespace) or os.curdir

        return namespace

    def get_tracked_dirs_inside(self, boundary, first=None):
        """Returns the tracked directories (and repositories) inside the given include boundary,
        first (a namespace) at the head of the list when it is one of them. Any of them can be a
        symbolic link out of the boundary, see :func:`open_include`."""
        root = os.path.abspath(boundary)
        dir_paths = [_ for _ in itertools.chain(self.tracked_dirs, self.tracked_repos)
                     if _is_inside(os.path.abspath(_), root)]
        if first in dir_paths:
            dir_paths.remove(first)
            dir_paths.insert(0, first)

        return dir_paths

    def _rule_file_refusal(self, namespace, file_path):
        """Why a rule file found by listing the directory of the namespace is not read, or None."""
        boundary = self.get_include_boundary(namespace)
        return rule_file_refusal(file_path, boundary, self.get_tracked_dirs_inside(boundary, first=namespace))

    def _rule_file_mtime(self, dir_path, file_path):
        """The modification time a file of a tracked directory is tracked by. A link out of the
        boundary is not read, so it is tracked by the link itself and not by what it points to."""
        if not self.allow_includes_outside and self._rule_file_refusal(dir_path, file_path):
            try:
                return os.lstat(file_path).st_mtime
            except OSError:
                return None

        return _getmtime(file_path)

    def track_yara_file(self, file_path, include_boundary=None):
        """Adds a single yara file.  The file is then monitored for changes to mtime, removal or adding.

        Its includes must stay inside include_boundary, which defaults to the directory the file is in."""
        if include_boundary is not None:
            self.include_boundaries[file_path] = include_boundary

        if not os.path.exists(file_path):
            self.tracked_files[file_path] = None  # file did not exist when we started tracking
            # we keep track of the path by keeping the key in the dictionary
            # so that if the file comes back we'll reload it
        else:
            self.tracked_files[file_path] = os.path.getmtime(file_path)

        log.debug("yara file {} tracked @ {}".format(file_path, self.tracked_files[file_path]))

    def track_yara_dir(self, dir_path, include_boundary=None):
        """Adds all files in a given directory that end with .yar when converted to lowercase.  All files are monitored for changes to mtime, as well as new and removed files.

        The includes of these files must stay inside include_boundary, which defaults to dir_path.
        Pass a directory above dir_path to let them reach files next to it."""
        if not os.path.isdir(dir_path):
            log.error("{} is not a directory".format(dir_path))
            return

        if include_boundary is not None:
            self.include_boundaries[dir_path] = include_boundary

        self.tracked_dirs[dir_path] = {}

        for file_path in os.listdir(dir_path):
            file_path = os.path.join(dir_path, file_path)
            if file_path.lower().endswith(".yar") or file_path.lower().endswith(".yara"):
                self.tracked_dirs[dir_path][file_path] = self._rule_file_mtime(dir_path, file_path)
                log.debug("tracking file {} @ {}".format(file_path, self.tracked_dirs[dir_path][file_path]))

        log.debug("tracking directory {} with {} yara files".format(dir_path, len(self.tracked_dirs[dir_path])))

    def track_yara_repository(self, dir_path, include_boundary=None):
        """Adds all files in a given directory **that is part of a git repository** that end with .yar when converted to lowercase.  Only commits to the repository trigger rule reload.

        The directory does not have to be the root of the repository. Any
        directory inside of one works, in which case the commit that is tracked
        (and reported with matching rules) is the current commit of the
        repository the directory belongs to.

        The includes of these files must stay inside include_boundary, which
        defaults to dir_path (not the root of the repository.) Pass the root of
        the repository to let them reach the rest of it."""
        if not self.git_available():
            log.warning("git cannot be found: defaulting to track_yara_dir")
            return self.track_yara_dir(dir_path, include_boundary=include_boundary)

        if not os.path.isdir(dir_path):
            log.error("{} is not a directory".format(dir_path))
            return False

        # get the initial commit of this directory
        # NOTE we do not look for a .git directory here because dir_path can be
        # a subdirectory of the repository, in which case .git is in a parent directory
        current_commit = get_current_repo_commit(dir_path)
        if current_commit is None:
            log.error("{} is not part of a git repository".format(dir_path))
            return False

        if include_boundary is not None:
            self.include_boundaries[dir_path] = include_boundary

        self.tracked_repos[dir_path] = current_commit
        log.debug("tracking git repo {} @ {}".format(dir_path, self.tracked_repos[dir_path]))

    def check_rules(self):
        """
        Returns True if the rules need to be recompiled or reloaded, False
        otherwise. The criteria that determines if the rules are recompiled
        depends on how they are tracked. Rules that were never loaded always
        need to be loaded (unless they are tracked as a compiled file.)

        :rtype: bool"""

        changed = self.rules_changed()
        if self.tracked_compiled_path:
            return changed

        # if we don't have a yara context yet then we def need to compile the rules
        return changed or self.rules is None

    def rules_changed(self):
        """
        Returns True if any tracked rule source changed since it was last
        tracked, False otherwise, and starts tracking the new state. Unlike
        :func:`YaraScanner.check_rules` this does not care whether rules were
        ever loaded, so it can be used to watch rules without compiling them.

        :rtype: bool"""

        if self.tracked_compiled_path:
            # did the file come back?
            if self.tracked_compiled_lastmtime is None and os.path.exists(self.tracked_compiled_path):
                log.info(f"detected recreated compiled yara file {self.tracked_compiled_path}")
                return True
            # was the file deleted?
            elif self.tracked_compiled_lastmtime is not None and not os.path.exists(self.tracked_compiled_path):
                log.info(f"detected deleted compiled yara file {self.tracked_compiled_path}")
                return False  # no reason to reload if we have nothing to load
            # was the file modified?
            elif os.path.getmtime(self.tracked_compiled_path) != self.tracked_compiled_lastmtime:
                log.info(f"detected change in compiled yara file {self.tracked_compiled_path}")
                return True
            else:
                # nothing changed, nothing to compare
                return False

        reload_rules = False  # final result to return

        for file_path in self.tracked_files.keys():
            # did the file come back?
            if self.tracked_files[file_path] is None and os.path.exists(file_path):
                log.info(f"detected recreated yara file {file_path}")
                self.track_yara_file(file_path)
                reload_rules = True
            # was the file deleted?
            elif self.tracked_files[file_path] is not None and not os.path.exists(file_path):
                log.info(f"detected deleted yara file {file_path}")
                self.track_yara_file(file_path)
                reload_rules = True
            # was the file modified?
            elif os.path.getmtime(file_path) != self.tracked_files[file_path]:
                log.info(f"detected change in yara file {file_path}")
                self.track_yara_file(file_path)
                reload_rules = True

        for dir_path in self.tracked_dirs.keys():
            reload_dir = False  # set to True if we need to reload this directory
            existing_files = set()  # keep track of the ones we see
            for file_path in os.listdir(dir_path):
                file_path = os.path.join(dir_path, file_path)
                if not (file_path.lower().endswith(".yar") or file_path.lower().endswith(".yara")):
                    continue

                existing_files.add(file_path)
                if file_path not in self.tracked_dirs[dir_path]:
                    log.info("detected new yara file {} in {}".format(file_path, dir_path))
                    reload_dir = True
                    reload_rules = True

                elif self._rule_file_mtime(dir_path, file_path) != self.tracked_dirs[dir_path][file_path]:
                    log.info("detected change in yara file {} dir {}".format(file_path, dir_path))
                    reload_dir = True
                    reload_rules = True

            # did a file get deleted?
            for file_path in self.tracked_dirs[dir_path].keys():
                if file_path not in existing_files:
                    log.info("detected deleted yara file {} in {}".format(file_path, dir_path))
                    reload_dir = True
                    reload_rules = True

            if reload_dir:
                self.track_yara_dir(dir_path)

        for repo_path in self.tracked_repos.keys():
            current_repo_commit = get_current_repo_commit(repo_path)
            # log.debug("repo {} current commit {} tracked commit {}".format(
            # repo_path, self.tracked_repos[repo_path], current_repo_commit))

            if current_repo_commit != self.tracked_repos[repo_path]:
                log.info("detected change in git repo {}".format(repo_path))
                self.track_yara_repository(repo_path)
                reload_rules = True

        return reload_rules

    def get_namespace_dict(self) -> Dict[str, List[str]]:
        """Returns a dictionary that contains lists of the tracked yara files organized by namespace."""

        # if we're using pre-compiled yara rules then you don't need this
        if self.tracked_compiled_path:
            return {}

        all_files = {}  # key = "namespace", value = [] of file_paths

        # XXX there's a bug in yara where using an empty string as the namespace causes a segfault
        #all_files["DEFAULT"] = [_ for _ in self.tracked_files.keys() if self.tracked_files[_] is not None]
        for tracked_file_path in self.tracked_files.keys():
            all_files[tracked_file_path] = [tracked_file_path]

        for dir_path in self.tracked_dirs.keys():
            all_files[dir_path] = self.tracked_dirs[dir_path]

        for repo_path in self.tracked_repos.keys():
            all_files[repo_path] = []
            for file_path in os.listdir(repo_path):
                file_path = os.path.join(repo_path, file_path)
                if file_path.lower().endswith(".yar") or file_path.lower().endswith(".yara"):
                    all_files[repo_path].append(file_path)

        return all_files

    def test_rules(self, test_config):
        if not test_config.test:
            return False

        if self.tracked_compiled_path:
            raise RuntimeError("cannot test compiled rules -- you need the source code to test the performance")

        all_files = self.get_namespace_dict()
        file_count = 0
        for namespace, file_list in all_files.items():
            file_count += len(file_list)

        # if we have no files to compile then we have nothing to do
        if file_count == 0:
            sys.stderr.write("ERROR: no yara files specified\n")
            return False

        # build the buffers we're going to use to test
        buffers = []  # [(buffer_name, buffer)]

        if test_config.test_data:  # random data to scan
            buffers.append(("random", test_config.test_data))
        else:
            buffers.append(("random", os.urandom(1024 * 1024)))

        for x in range(255):
            buffers.append((f"chr({x})", bytes([x]) * (1024 * 1024)))

        execution_times = []  # of (total_seconds, buffer_type, file_name, rule_name)
        execution_errors = []  # of (error_message, buffer_type, file_name, rule_name)
        string_execution_times = []
        string_errors = []

        bar = progress.bar.Bar("decompiling rules", max=file_count)
        parsed_rules = {}  # key = rule_name, value = parsed_yara_rule
        yara_sources = {}  # key = rule_name, value = yara_source_string
        yara_files = {}  # key = rule_name, value = file it came from
        for namespace, file_list in all_files.items():
            for file_path in file_list:
                if test_config.show_progress_bar:
                    bar.next()

                with open(file_path, "r") as fp:
                    yara_source = fp.read()

                parser = plyara.Plyara()
                for parsed_rule in parser.parse_string(yara_source):
                    # if we specified a rule to test then discard the others
                    if test_config.test_rule and parsed_rule["rule_name"] != test_config.test_rule:
                        continue

                    parsed_rules[parsed_rule["rule_name"]] = parsed_rule
                    yara_sources[parsed_rule["rule_name"]] = yara_source
                    yara_files[parsed_rule["rule_name"]] = file_path

        if test_config.show_progress_bar:
            bar.finish()

        steps = len(parsed_rules) * 256

        class FancyBar(progress.bar.Bar):
            message = "testing"
            suffix = "%(percent).1f%% - %(eta_hms)s - %(rule)s (%(buffer)s)"
            rule = None
            buffer = None

            @property
            def eta_hms(self):
                seconds = self.eta
                seconds = seconds % (24 * 3600)
                hour = seconds // 3600
                seconds %= 3600
                minutes = seconds // 60
                seconds %= 60

                return "%d:%02d:%02d" % (hour, minutes, seconds)

        bar = FancyBar(max=steps)

        for rule_name in parsed_rules.keys():
            bar.rule = rule_name
            # some rules depend on other rules, so we deal with that here
            dependencies = []  # list of rule_names that this rule needs
            rule_context = None

            while True:
                # compile all the rules we've collected so far as one
                dep_source = "\n".join([plyara.utils.rebuild_yara_rule(parsed_rules[r]) for r in dependencies])
                try:
                    rule_context = yara.compile(
                        source="{}\n{}".format(dep_source, plyara.utils.rebuild_yara_rule(parsed_rules[rule_name]))
                    )
                    break
                except Exception as e:
                    # some rules depend on other rules
                    m = re.search(r'undefined identifier "([^"]+)"', str(e))
                    if m:
                        dependency = m.group(1)
                        if dependency in parsed_rules:
                            # add this rule to the compilation and try again
                            dependencies.insert(0, dependency)
                            continue

                    sys.stderr.write(
                        "rule {} in file {} does not compile by itself: {}\n".format(
                            rule_name, yara_files[rule_name], e
                        )
                    )
                    rule_context = None
                    break

            if not rule_context:
                continue

            trigger_test_strings = False
            for buffer_name, buffer in buffers:
                try:
                    bar.buffer = buffer_name
                    if test_config.show_progress_bar:
                        bar.next()
                    start_time = time.time()
                    rule_context.match(data=buffer, timeout=5)
                    end_time = time.time()
                    total_seconds = end_time - start_time
                    execution_times.append([buffer_name, yara_files[rule_name], rule_name, total_seconds])
                    if test_config.test_strings_if and total_seconds > test_config.test_strings_threshold:
                        trigger_test_strings = True
                except Exception as e:
                    execution_errors.append([buffer_name, yara_files[rule_name], rule_name, str(e)])
                    if test_config.test_strings_if:
                        trigger_test_strings = True

            if test_config.test_strings or trigger_test_strings:
                parser = plyara.Plyara()
                parsed_rule = None

                for _ in parser.parse_string(yara_sources[rule_name]):
                    if _["rule_name"] == rule_name:
                        parsed_rule = _

                if not parsed_rule:
                    sys.stderr.write(f"no rule named {rule_name} in {yara_files[rule_name]}\n")
                    continue

                string_count = 1
                for string in parsed_rule["strings"]:
                    if string["type"] == "regex":
                        string_count += 1

                class FancyStringBar(progress.bar.Bar):
                    message = "processing"
                    suffix = "%(percent).1f%% - %(eta_hms)s - %(rule)s %(string)s (%(buffer)s)"
                    rule = None
                    string = None
                    buffer = None

                    @property
                    def eta_hms(self):
                        seconds = self.eta
                        seconds = seconds % (24 * 3600)
                        hour = seconds // 3600
                        seconds %= 3600
                        minutes = seconds // 60
                        seconds %= 60

                        return "%d:%02d:%02d" % (hour, minutes, seconds)

                string_bar = FancyStringBar(max=string_count * 256)
                string_bar.rule = rule_name

                for string in parsed_rule["strings"]:
                    if string["type"] == "regex":
                        string_bar.string = string["value"]
                        try:
                            string_name = string["name"]
                            string_value = string["value"]
                            temp_rule = f"""
                            rule temp_rule {{
                            strings:
                            $ = {string_value}
                            condition:
                            any of them
                            }}"""

                            string_rule_context = yara.compile(source=temp_rule)
                            for buffer_name, buffer in buffers:
                                string_bar.buffer = buffer_name
                                try:
                                    start_time = time.time()
                                    scan_result = string_rule_context.match(data=buffer, timeout=5)
                                    end_time = time.time()
                                    string_execution_times.append(
                                        [
                                            buffer_name,
                                            yara_files[rule_name],
                                            rule_name,
                                            string_name,
                                            len(scan_result),
                                            end_time - start_time,
                                        ]
                                    )
                                except Exception as e:
                                    string_errors.append(
                                        [buffer_name, yara_files[rule_name], rule_name, string_name, str(e)]
                                    )

                                if test_config.show_progress_bar:
                                    string_bar.next()
                        except Exception as e:
                            sys.stderr.write(f"failed to test string {string_name}: {e}\n")
                            string_errors.append(["N/A", yara_files[rule_name], rule_name, string_name, str(e)])

                if test_config.show_progress_bar:
                    string_bar.finish()

        if test_config.show_progress_bar:
            bar.finish()

        # order by execution time
        execution_times = sorted(execution_times, key=itemgetter(3), reverse=True)
        string_execution_times = sorted(string_execution_times, key=itemgetter(5), reverse=True)

        if test_config.csv or test_config.performance_csv:
            with open(test_config.csv or test_config.performance_csv, "w", newline="") as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "time"])
                for row in execution_times:
                    writer.writerow(row)
        else:
            print("BEGIN EXECUTION TIME")
            for row in execution_times:
                print(row)
            print("END EXECUTION TIME")

        if test_config.csv or test_config.failure_csv:
            with open(test_config.csv or test_config.failure_csv, "a" if test_config.csv else "w", newline="") as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "error"])
                for row in execution_errors:
                    writer.writerow(row)
        else:
            print("BEGIN EXECUTION ERRORS")
            for row in execution_errors:
                print(row)
            print("END EXECUTION ERRORS")

        if test_config.csv or test_config.string_performance_csv:
            with open(
                test_config.csv or test_config.string_performance_csv, "a" if test_config.csv else "w", newline=""
            ) as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "string", "hits", "time"])
                for row in string_execution_times:
                    writer.writerow(row)
        else:
            print("BEGIN STRING EXECUTION TIME")
            for row in string_execution_times:
                print(row)
            print("END STRING EXECUTION TIME")

        if test_config.csv or test_config.string_failure_csv:
            with open(
                test_config.csv or test_config.string_failure_csv, "a" if test_config.csv else "w", newline=""
            ) as fp:
                writer = csv.writer(fp)
                writer.writerow(["buffer", "file", "rule", "string", "error"])
                for row in string_errors:
                    writer.writerow(row)
        else:
            print("BEGIN STRING EXECUTION ERRORS")
            for row in string_errors:
                print(row)
            print("END STRING EXECUTION ERRORS")

    def load_rules(self, external_vars=DEFAULT_YARA_EXTERNALS):
        if self.auto_compile_rules:
            namespaces = self.get_namespace_dict()
            suffix = ".cyar"
            if not self.allow_includes_outside:
                # a rule file that is not read is not hashed either, and rules that were compiled
                # with includes read from anywhere are not the rules of a load that is bounded
                suffix = ".bounded.cyar"
                namespaces = {
                    namespace: [
                        _ for _ in file_paths
                        if namespace in self.tracked_files
                        or self._rule_file_refusal(namespace, _) is None
                    ]
                    for namespace, file_paths in namespaces.items()
                }

            rules_hash = get_rules_md5(namespaces)
            compiled_rules_path = os.path.join(self.auto_compiled_rules_dir, f"{rules_hash}{suffix}")
            if self.load_compiled_rules(compiled_rules_path):
                return True

        if self.compile_and_load_rules(external_vars=external_vars):
            if self.auto_compile_rules:
                self.save_compiled_rules(compiled_rules_path)
            return True
        else:
            return False

    def load_compiled_rules(self, path):
        try:
            if os.path.isfile(path):
                log.debug(f"up to date compiled rules already exist at {path}")
                self.rules = yara.load(path)
                self.compiled_sources = []
                self.compile_error = None
                return True
        except:
            log.warning(f"failed to load compiled rules: {path}")

        return False

    def save_compiled_rules(self, path):
        try:
            self.rules.save(path)
            os.chmod(path, 0o666)  # XXX ???
            return True
        except Exception as e:
            log.warning(f"failed to save compiled rules {path}: {e}")

        return False

    def compile_and_load_rules(self, external_vars=DEFAULT_YARA_EXTERNALS):
        """
        Loads and compiles all tracked yara rules. Returns True if the rules were loaded correctly, False otherwise.

        Each file is compiled on its own first, and a file that fails is left out. The files that
        compile are then compiled together, one source per namespace, into the rules scans use.
        What was compiled is kept in :attr:`compiled_sources` (one :class:`CompiledSource` per file
        read, in the order read) and the error of the combined compile in :attr:`compile_error`.

        Scans can be performed only after the rules are loaded.

        :rtype: bool"""

        self.compiled_sources = []
        self.compile_error = None

        # the file being compiled on its own, which its top-level includes resolve against and which
        # records them; None while the files are compiled together
        current: Optional[CompiledSource] = None

        # requested name -> the path it resolved to, in the compile in progress. yara gives the
        # callback of a nested include the name its parent was requested by, not the parent's path.
        # When two includes requested by the same name resolve to different paths, the later wins.
        parents: Dict[str, str] = {}

        # (namespace, the parent's resolved path or None, requested name) -> the IncludedSource read
        # for it. Both passes make the same calls for an include, so the combined compile gets the
        # text the file compiled with on its own, not a second read of a file that may have changed
        includes: Dict[tuple, IncludedSource] = {}

        def read_include(requested_filename: str, parent: Optional[str], namespace: str) -> IncludedSource:
            # an include is relative to the file that has the include statement
            if parent is not None:
                dir_name = os.path.dirname(parent)
            elif current is not None:
                dir_name = os.path.dirname(current.path)
            else:
                # the combined compile names each namespace after its directory
                dir_name = namespace

            relative_path = os.path.join(dir_name, requested_filename)

            try:
                if self.allow_includes_outside:
                    fp = open(relative_path, "r")
                else:
                    # refused before it is opened unless it is a regular file inside the boundary
                    boundary = self.get_include_boundary(namespace if current is None else current.namespace)
                    fp = open_include(dir_name, requested_filename, boundary, self.get_tracked_dirs_inside(boundary))

                with fp:
                    return IncludedSource(requested_filename, relative_path, fp.read())
            except Exception as e:
                log.error("unable to include file %s: %s", relative_path, e)
                return IncludedSource(requested_filename, relative_path, "", str(e))

        def include_callback(requested_filename: str, filename: Optional[str], namespace: str) -> str:
            parent = None if filename is None else parents.get(filename)
            key = (namespace if current is None else current.namespace, parent, requested_filename)
            if key not in includes:
                if current is None:
                    # every file in the combined compile made its include calls when it compiled on its own
                    log.warning("include %s from namespace %s was not read when its file compiled on its own",
                                requested_filename, namespace)

                includes[key] = read_include(requested_filename, parent, namespace)

            included = includes[key]
            parents[requested_filename] = included.path
            if current is not None:
                current.includes.append(included)

            return included.source

        if self.tracked_compiled_path:
            try:
                self.tracked_compiled_lastmtime = os.path.getmtime(self.tracked_compiled_path)
                self.rules = yara.load(self.tracked_compiled_path)
                return True
            except FileNotFoundError:
                self.tracked_compiled_lastmtime = None
                return False
            except Exception as e:
                log.error("unable to load {self.tracked_compiled_path}: {e}")
                return False

        # load and compile the rules
        # we load all the rules into memory as a string to be compiled
        sources = {}
        rule_count = 0
        file_count = 0

        all_files = self.get_namespace_dict()
        file_count = sum([len(_) for _ in all_files.values()])

        # if we have no files to compile then we have nothing to do
        if file_count == 0:
            logging.debug("no files to compile")
            self.rules = None
            return False

        compilation_errors = False

        for namespace in all_files.keys():
            for file_path in all_files[namespace]:

                log.debug("loading namespace {} rule file {}".format(namespace, file_path))
                try:
                    # a file the caller tracked by name is read whatever it is; one found by listing
                    # a directory must not be a link out of the boundary
                    if not self.allow_includes_outside and namespace not in self.tracked_files:
                        refusal = self._rule_file_refusal(namespace, file_path)
                        if refusal is not None:
                            raise IncludeRefusedError(refusal)

                    with open(file_path, "r") as fp:
                        data = fp.read()
                except FileNotFoundError:
                    # a tracked file that was removed, perhaps since it was listed
                    log.debug("file %s does not exist", file_path)
                    continue
                except (OSError, UnicodeDecodeError, IncludeRefusedError) as e:
                    # like a file that does not compile, it is left out and the rest are loaded
                    log.error("unable to read {}: {}".format(file_path, e))
                    self.compiled_sources.append(CompiledSource(file_path, namespace, "", error=str(e)))
                    compilation_errors = True
                    continue

                current = CompiledSource(file_path, namespace, data)
                self.compiled_sources.append(current)
                parents.clear()

                try:
                    # compile each file individually first, make sure that works
                    rule_context = yara.compile(source=data, externals=external_vars, include_callback=include_callback)
                    rule_count += 1
                except Exception as e:
                    log.error("unable to compile {}: {}".format(file_path, str(e)))
                    current.error = str(e)
                    compilation_errors = True
                    continue

                current.warnings = list(rule_context.warnings or [])
                current.rules = [rule.identifier for rule in rule_context]

                # then we just store the source to be loaded all at once in the compilation that gets used
                if namespace not in sources:
                    sources[namespace] = []

                sources[namespace].append(data)

        for namespace in sources.keys():
            sources[namespace] = "\r\n".join(sources[namespace])

        current = None
        parents.clear()

        try:
            log.info("loading {} rules".format(rule_count))
            self.rules = yara.compile(sources=sources, externals=external_vars, include_callback=include_callback)
            return not compilation_errors
        except Exception as e:
            log.error(f"unable to compile all yara rules combined: {e}")
            self.compile_error = str(e)
            self.rules = None

        return False

    # we're keeping things backwards compatible here...
    def scan(self, file_path, yara_stdout_file=None, yara_stderr_file=None, external_vars={}, timeout=None, meta_tags=None):
        """
        Scans the given file with the loaded yara rules. Returns True if at least one yara rule matches, False otherwise.

        The ``scan_results`` property will contain the results of the scan.

        :param file_path: The path to the file to scan.
        :type file_path: str
        :param yara_stdout_file: Ignored.
        :param yara_stderr_file: Ignored.
        :external_vars: dict of variables to pass to the scanner as external yara variables (typically used in the condition of the rule.)
        :type external_vars: dict
        :rtype: bool
        """

        # default external variables
        default_external_vars = {
            "filename": os.path.basename(file_path),
            "filepath": file_path,
            "filetype": "",  # get_the_file_type(),
            "extension": file_path.rsplit(".", maxsplit=1)[1] if "." in file_path else "",
        }
        # update with whatever is passed in
        default_external_vars.update(external_vars)

        if not timeout:
            timeout = self.default_timeout

        if self.rules is None:
            self.load_rules()
            if self.rules is None:
                raise RulesNotLoadedError()

        # scan the file
        # external variables come from the profile points added to the file
        if timeout == 0:
            yara_matches = self.rules.match(file_path, externals=default_external_vars)
        else:
            yara_matches = self.rules.match(file_path, externals=default_external_vars, timeout=timeout)

        return self.filter_scan_results(
            file_path, None, yara_matches, yara_stdout_file, yara_stderr_file, external_vars,
            meta_tags=meta_tags,
        )

    def scan_data(self, data, yara_stdout_file=None, yara_stderr_file=None, external_vars={}, timeout=None, meta_tags=None):
        """
        Scans the given data with the loaded yara rules. ``data`` can be either a str or bytes object. Returns True if at least one yara rule matches, False otherwise.

        The ``scan_results`` property will contain the results of the scan.

        :param data: The data to scan.
        :type data: str or bytes
        :param yara_stdout_file: Ignored.
        :param yara_stderr_file: Ignored.
        :external_vars: dict of variables to pass to the scanner as external yara variables (typically used in the condition of the rule.)
        :type external_vars: dict
        :rtype: bool
        """

        assert self.rules is not None

        if not timeout:
            timeout = self.default_timeout

        # scan the data stream
        # external variables come from the profile points added to the file
        yara_matches = self.rules.match(data=data, externals=external_vars, timeout=timeout)
        return self.filter_scan_results(None, data, yara_matches, yara_stdout_file, yara_stderr_file, external_vars,
                                        meta_tags=meta_tags)

    def filter_scan_results(
        self, file_path, data, yara_matches, yara_stdout_file=None, yara_stderr_file=None, external_vars={},
        meta_tags=None,
    ):

        # if we didn't specify a file_path then we default to an empty string
        # that will be the case when we are scanning a data chunk
        if file_path is None:
            file_path = ""

        # the mime type of the file
        # we'll figure it out if we need to
        mime_type = None

        # the list of matches after we filter
        scan_results = []

        for match_result in yara_matches:
            skip = False  # state flag

            # is this a rule we've blacklisted?
            if match_result.rule in self.blacklist:
                log.debug("rule {} is blacklisted".format(match_result.rule))
                continue

            for directive in match_result.meta:
                value = match_result.meta[directive]

                # everything we're looking for is a string
                if not isinstance(value, str):
                    continue

                # you can invert the logic by starting the value with !
                inverted = False
                if value.startswith("!"):
                    value = value[1:]
                    inverted = True

                # you can use regex by starting string with re: (after optional negation)
                use_regex = False
                if value.startswith("re:"):
                    value = value[3:]
                    use_regex = True

                # or you can use substring matching with sub:
                use_substring = False
                if value.startswith("sub:"):
                    value = value[4:]
                    use_substring = True

                # figure out what we're going to compare against
                compare_target = None
                if directive.lower() == "file_ext":
                    if "." not in file_path:
                        compare_target = ""
                    else:
                        compare_target = file_path.rsplit(".", maxsplit=1)[1]

                elif directive.lower() == "mime_type":
                    # have we determined the mime type for this file yet?
                    if mime_type is None:
                        if not file_path:
                            mime_type = ""
                        else:
                            p = Popen(["file", "-b", "--mime-type", file_path], stdout=PIPE)
                            mime_type = p.stdout.read().decode().strip()
                            log.debug("got mime type {} for {}".format(mime_type, file_path))

                    compare_target = mime_type

                elif directive.lower() == "file_name":
                    compare_target = os.path.basename(file_path)

                elif directive.lower() == "full_path":
                    compare_target = file_path

                elif directive.lower() == "meta_tags":
                    # meta_tags is special: we compare each rule-specified tag against each caller-provided tag
                    caller_tags = meta_tags or []

                    if not caller_tags:
                        # no tags provided by caller
                        if not inverted:
                            # non-inverted: rule wants specific tags but none provided -> skip
                            skip = True
                            break
                        else:
                            # inverted: rule says "NOT these tags" and none provided -> don't skip
                            continue

                    # build compare function
                    if use_regex:
                        compare_function = lambda user_supplied, target: re.search(user_supplied, target, re.IGNORECASE)
                    elif use_substring:
                        compare_function = lambda user_supplied, target: user_supplied.lower() in target.lower()
                    else:
                        compare_function = lambda user_supplied, target: user_supplied.lower() == target.lower()

                    # cross-product: any rule value matches any caller tag
                    matches = False
                    for search_item in [x.strip() for x in value.lower().split(",")]:
                        for caller_tag in caller_tags:
                            matches = matches or compare_function(search_item, caller_tag)

                    if (inverted and matches) or (not inverted and not matches):
                        log.debug(
                            "skipping yara rule {} directive {} list {} negated {} regex {} subsearch {}".format(
                                match_result.rule, directive, value, inverted, use_regex, use_substring
                            )
                        )
                        skip = True
                        break

                    continue

                else:
                    # not a meta tag we're using
                    # log.debug("not a valid meta directive {}".format(directive))
                    continue

                log.debug("compare target is {} for directive {}".format(compare_target, directive))

                # figure out how to compare what is supplied by the user to the search target
                if use_regex:
                    compare_function = lambda user_supplied, target: re.search(user_supplied, target, re.IGNORECASE)
                elif use_substring:
                    compare_function = lambda user_supplied, target: user_supplied.lower() in target.lower()
                else:
                    compare_function = lambda user_supplied, target: user_supplied.lower() == target.lower()

                matches = False
                for search_item in [x.strip() for x in value.lower().split(",")]:
                    matches = matches or compare_function(search_item, compare_target)
                    # log.debug("search item {} vs compare target {} matches {}".format(search_item, compare_target, matches))

                if (inverted and matches) or (not inverted and not matches):
                    log.debug(
                        "skipping yara rule {} for file {} directive {} list {} negated {} regex {} subsearch {}".format(
                            match_result.rule, file_path, directive, value, inverted, use_regex, use_substring
                        )
                    )
                    skip = True
                    break  # we are skipping so we don't need to check anything else

            if not skip:
                scan_results.append(match_result)

        # get rid of the yara object and just return dict
        # also includes a "target" (reference to what was scanned)
        self.scan_results = []
        
        for result in scan_results:
            # compute strings tuple
            strings = []
            for string_match in result.strings:
                string_identifier = string_match.identifier
                for string_instance in string_match.instances:
                    strings.append((string_instance.offset, string_identifier, string_instance.matched_data))

            self.scan_results.append({
                "target": file_path,
                "meta": result.meta,
                "namespace": result.namespace,
                "commit": self.tracked_repos.get(result.namespace),
                "rule": result.rule,
                "strings": strings,
                "tags": result.tags,
            })

        #self.scan_results = [
            #{
                #"target": file_path,
                #"meta": o.meta,
                #"namespace": o.namespace,
                #"rule": o.rule,
                #"strings": o.strings,
                #"tags": o.tags,
            #}
            #for o in self.scan_results
        #]

        # this is for backwards compatible support
        if yara_stdout_file is not None:
            try:
                with open(yara_stdout_file, "w") as fp:
                    json.dump(self.scan_results, fp, indent=4, sort_keys=True)
            except Exception as e:
                log.error("unable to write to {}: {}".format(yara_stdout_file, str(e)))

        return self.has_matches

    @property
    def has_matches(self):
        return len(self.scan_results) != 0


class TestConfig:
    test = False
    test_rule = None
    test_strings = False
    test_strings_if = False
    test_strings_threshold = 0.1
    test_data = None
    csv = None
    performance_csv = None
    failure_csv = None
    string_performance_csv = None
    string_failure_csv = None
    show_progress_bar = False


def main():
    import argparse
    import pprint
    import sys

    parser = argparse.ArgumentParser(description="Scan the given file with yara using all available rulesets.")
    parser.add_argument("paths", metavar="PATHS", nargs="*", help="One or more files or directories to scan with yara.")
    parser.add_argument(
        "-r",
        "--recursive",
        required=False,
        default=False,
        action="store_true",
        dest="recursive",
        help="Recursively scan directories.",
    )
    parser.add_argument(
        "--from-stdin",
        required=False,
        default=False,
        action="store_true",
        dest="from_stdin",
        help="Read the list of files to scan from stdin.",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        action="count",
        default=0,
        help="Increase verbosity. Can specify multiple times for more verbose output",
    )
    parser.add_argument(
        "-j",
        "--dump-json",
        required=False,
        default=False,
        action="store_true",
        dest="dump_json",
        help="Dump JSON details of matches.  Otherwise just list the rules that hit.",
    )

    parser.add_argument(
        "-t",
        "--test",
        required=False,
        default=False,
        action="store_true",
        dest="test",
        help="Test each yara file separately against different types of buffers for performance issues.",
    )
    parser.add_argument("--test-rule", required=False, default=None, dest="test_rule", help="Tests a specific rule.")
    parser.add_argument(
        "--test-strings",
        required=False,
        default=False,
        action="store_true",
        dest="test_strings",
        help="Tests the performance all the strings individually in the selected yara rules.",
    )
    parser.add_argument(
        "--test-strings-if",
        required=False,
        default=False,
        action="store_true",
        dest="test_strings_if",
        help="""Tests the performance all the strings individually in rules
        that take longer than N seconds to complete or rules that fail for any
        reason.""",
    )
    parser.add_argument(
        "--test-strings-threshold",
        required=False,
        default=0.1,
        type=float,
        dest="test_strings_threshold",
        help="The threshold (in seconds) for the --test-strings-if option. Defaults to 0.1 seconds.",
    )
    parser.add_argument(
        "--test-data",
        required=False,
        default=None,
        dest="test_data",
        help="Use the given file as the buffer of random data for the test data.",
    )
    parser.add_argument("--csv", help="Write performance results to the given CSV file.")
    parser.add_argument(
        "--performance-csv",
        required=False,
        default=None,
        dest="performance_csv",
        help="Write the performance results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--failure-csv",
        required=False,
        default=None,
        dest="failure_csv",
        help="Write the failure results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--string-performance-csv",
        required=False,
        default=None,
        dest="string_performance_csv",
        help="Write the performance results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--string-failure-csv",
        required=False,
        default=None,
        dest="string_failure_csv",
        help="Write the failure results of string testing to the given csv formatted file. Defaults to stdout.",
    )
    parser.add_argument(
        "--no-progress-bar", default=False, action="store_true", help="Disable the progress bar shown during testing."
    )

    parser.add_argument(
        "-y",
        "--yara-rules",
        required=False,
        default=[],
        action="append",
        dest="yara_rules",
        help="One yara rule to load.  You can specify more than one of these.",
    )
    parser.add_argument(
        "-Y",
        "--yara-dirs",
        required=False,
        default=[],
        action="append",
        dest="yara_dirs",
        help="One directory containing yara rules to load.  You can specify more than one of these.",
    )
    parser.add_argument(
        "-G",
        "--yara-repos",
        required=False,
        default=[],
        action="append",
        dest="yara_repos",
        help="One directory that is part of a git repository that contains yara rules to load. You can specify more than one of these.",
    )
    parser.add_argument(
        "-z",
        "--compiled-yara-rules",
        help="Load compiled yara rules from the specified files. This option cannot be combined with -y, -Y, or -G",
    )

    parser.add_argument(
        "-c",
        "--compile-only",
        required=False,
        default=False,
        action="store_true",
        dest="compile_only",
        help="Compile the rules and exit.",
    )

    parser.add_argument("-C", "--compile-to", help="Compile the rules into the given file path.")
    parser.add_argument(
        "-b",
        "--blacklist",
        required=False,
        default=[],
        action="append",
        dest="blacklisted_rules",
        help="A rule to blacklist (remove from the results.)  You can specify more than one of these options.",
    )
    parser.add_argument(
        "-B",
        "--blacklist-path",
        required=False,
        default=None,
        dest="blacklisted_rules_path",
        help="Path to a file that contains a list of rules to blacklist, one per line.",
    )

    parser.add_argument(
        "--meta-tags",
        required=False,
        default=[],
        action="append",
        dest="meta_tags",
        help="A meta tag to pass to the scanner for rule filtering. You can specify more than one of these options.",
    )

    parser.add_argument(
        "-a",
        "--auto-compile-rules",
        default=False,
        action="store_true",
        help="""Automatically saved the compiled yara rules to disk.
        Automatically loads pre-compiled rules based on MD5 hash of rule
        content.""",
    )
    parser.add_argument(
        "--auto-compiled-rules-dir",
        help="""Specifies the directory to use to store automatically compiled
        yara rules. Defaults to the system temp dir.""",
    )

    parser.add_argument(
        "-d",
        "--signature-dir",
        dest="signature_dir",
        default=None,
        help="DEPRECATED: Use a different signature directory than the default.",
    )

    parser.add_argument(
        "--git-repo-dir",
        required=False,
        default=[],
        action="append",
        dest="git_repo_dirs",
        help="""A subdirectory of --signature-dir that is part of a git
        repository. Only commits to the repository trigger a rule reload and
        matching rules report the commit. You can specify more than one of
        these.""",
    )

    parser.add_argument(
        "--allow-includes-outside",
        default=False,
        action="store_true",
        help="""Let an include statement read any file, and a rule file be a
        link to any file. By default an include must be a regular file inside
        the directory its rules were loaded from (the signature directory for
        the directories in it), reached through no symbolic link.""",
    )

    args = parser.parse_args()

    if (
        len(args.yara_rules) == 0
        and len(args.yara_dirs) == 0
        and len(args.yara_repos) == 0
        and args.signature_dir is None
    ):
        args.signature_dir = "/opt/signatures"

    log_levels = {0: logging.ERROR, 1: logging.WARNING, 2: logging.INFO, 3: logging.DEBUG}
    log_level = min(max(args.verbose, 0), 3)  # clamp to 0-3 inclusive
    logging.basicConfig(level=log_levels[log_level])

    # load any blacklisting
    if args.blacklisted_rules_path is not None:
        with open(args.blacklisted_rules_path, "r") as fp:
            args.blacklisted_rules.extend([x.strip() for x in fp.read().split("\n")])

    scanner = YaraScanner(
        signature_dir=args.signature_dir,
        auto_compile_rules=args.auto_compile_rules,
        auto_compiled_rules_dir=args.auto_compiled_rules_dir,
        git_repo_dirs=args.git_repo_dirs,
        allow_includes_outside=args.allow_includes_outside,
    )
    scanner.blacklist = args.blacklisted_rules

    if args.compiled_yara_rules:
        scanner.track_compiled_yara_file(args.compiled_yara_rules)
    else:
        for file_path in args.yara_rules:
            scanner.track_yara_file(file_path)

        for dir_path in args.yara_dirs:
            scanner.track_yara_dir(dir_path)

        for repo_path in args.yara_repos:
            scanner.track_yara_repository(repo_path)

    if not scanner.load_rules():
        sys.exit(1)

    if args.compile_to:
        scanner.save_compiled_rules(args.compile_to)
        sys.exit(0)

    if args.test:
        test_config = TestConfig()
        test_config.test = args.test
        test_config.test_rule = args.test_rule
        test_config.test_strings = args.test_strings
        test_config.test_strings_if = args.test_strings_if
        test_config.test_strings_threshold = args.test_strings_threshold
        if args.test_data:
            with open(args.test_data, "rb") as fp:
                test_config.test_data = fp.read()
        test_config.csv = args.csv
        test_config.performance_csv = args.performance_csv
        test_config.failure_csv = args.failure_csv
        test_config.string_performance_csv = args.string_performance_csv
        test_config.string_failure_csv = args.string_failure_csv
        test_config.show_progress_bar = not args.no_progress_bar
        scanner.test_rules(test_config)
        sys.exit(0)

    if scanner.check_rules():
        scanner.load_rules()

    if args.compile_only or args.test or args.compile_to:
        sys.exit(0)

    exit_result = 0

    def scan_file(file_path):
        global exit_result
        try:
            if scanner.scan(file_path, meta_tags=args.meta_tags or None):
                if args.dump_json:
                    json.dump(scanner.scan_results, sys.stdout, sort_keys=True, indent=4, cls=YaraJSONEncoder)
                else:
                    print(file_path)
                    for match in scanner.scan_results:
                        if match["commit"]:
                            print("\t{} ({})".format(match["rule"], match["commit"]))
                        else:
                            print("\t{}".format(match["rule"]))
        except Exception as e:
            log.error("scan failed for {}: {}".format(file_path, e))
            exit_result = 1

    def scan_dir(dir_path):
        for file_path in os.listdir(dir_path):
            file_path = os.path.join(dir_path, file_path)
            if os.path.isdir(file_path):
                if args.recursive:
                    scan_dir(file_path)
            else:
                scan_file(file_path)

    if args.from_stdin:
        for line in sys.stdin:
            line = line.strip()
            scan_file(line)
    else:
        for path in args.paths:
            if os.path.isdir(path):
                scan_dir(path)
            else:
                scan_file(path)

    sys.exit(exit_result)


if __name__ == "__main__":
    main()
