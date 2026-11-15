import logging
import os.path
import shutil
import time

from subprocess import Popen

import pytest
import yara

import yara_scanner

from yara_scanner import (ALL_RESULT_KEYS, RESULT_KEY_COMMIT, RESULT_KEY_META,
                          RESULT_KEY_NAMESPACE, RESULT_KEY_RULE,
                          RESULT_KEY_STRINGS, RESULT_KEY_TAGS,
                          RESULT_KEY_TARGET, YaraScanner, __version__, RulesNotLoadedError,
                          get_current_repo_commit, CompiledSource, IncludedSource)

def create_file(path, content):
    dir = os.path.dirname(path)
    if not os.path.isdir(dir):
        os.makedirs(dir)

    with open(path, 'w') as fp:
        fp.write(content)

    return path

@pytest.fixture
def scanner(shared_datadir):
    s = YaraScanner(signature_dir=str(shared_datadir / 'signatures'))
    s.load_rules()
    return s

@pytest.fixture
def repo(shared_datadir):
    repo_path = str(shared_datadir / 'signatures' / 'ruleset_a')
    Popen(['git', '-C', repo_path, 'init']).wait()
    Popen(['git', '-C', repo_path, 'config', 'user.name', 'Test User']).wait()
    Popen(['git', '-C', repo_path, 'config', 'user.email', 'test_user@localhost']).wait()
    Popen(['git', '-C', repo_path, 'add', '*.yar']).wait()
    Popen(['git', '-C', repo_path, 'commit', '-m', 'initial commit']).wait()
    return repo_path

@pytest.fixture
def parent_repo(shared_datadir):
    # a git repository that *contains* the signature directory
    # the rule directories are inside of it but have no .git directory of their own
    repo_path = str(shared_datadir)
    Popen(['git', '-C', repo_path, 'init']).wait()
    Popen(['git', '-C', repo_path, 'config', 'user.name', 'Test User']).wait()
    Popen(['git', '-C', repo_path, 'config', 'user.email', 'test_user@localhost']).wait()
    Popen(['git', '-C', repo_path, 'add', '-A']).wait()
    Popen(['git', '-C', repo_path, 'commit', '-m', 'initial commit']).wait()
    return repo_path

@pytest.mark.integration
def test_signature_dir_load(scanner):
    # there should be two loaded directories
    assert len(scanner.tracked_dirs) == 2
    for dir_name in scanner.tracked_dirs.keys():
        # and one file from each directory
        assert len(scanner.tracked_dirs[dir_name]) == 1

    assert not scanner.check_rules()
    assert scanner.load_rules()

@pytest.mark.integration
def test_data_scan_matching(scanner):
    # this should match
    assert scanner.scan_data('test_rule_1')
    # this should also match
    assert scanner.scan_data(b'test_rule_1')
    # this should not match
    assert not scanner.scan_data('random data')

@pytest.mark.integration
def test_data_scan_results(scanner):
    scanner.scan_data('test_rule_1')
    # this should match tests/data/signatures/ruleset_a/rule_1.yar
    assert len(scanner.scan_results) == 1
    for key in ALL_RESULT_KEYS:
        assert key in scanner.scan_results[0]

    assert scanner.scan_results[0][RESULT_KEY_TARGET] == ''
    assert scanner.scan_results[0][RESULT_KEY_META] == {}
    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_NAMESPACE]) == 'ruleset_a'
    # directory-tracked rules are not from a git repo, so there is no commit
    assert scanner.scan_results[0][RESULT_KEY_COMMIT] is None
    assert scanner.scan_results[0][RESULT_KEY_RULE] == 'rule_1'
    assert scanner.scan_results[0][RESULT_KEY_STRINGS] == [(0, '$', b'test_rule_1')]
    assert scanner.scan_results[0][RESULT_KEY_TAGS] == ['tag_1']

    scanner.scan_data('test_rule_1\ntest_rule_2\n')
    # this should match both rules
    assert len(scanner.scan_results) == 2

@pytest.mark.integration
def test_file_scan_results(scanner, shared_datadir):
    assert scanner.scan(str(shared_datadir / 'scan_targets' / 'scan_target_1.txt'))

    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_TARGET]) == 'scan_target_1.txt'
    assert scanner.scan_results[0][RESULT_KEY_META] == {}
    assert os.path.basename(scanner.scan_results[0][RESULT_KEY_NAMESPACE]) == 'ruleset_a'
    # directory-tracked rules are not from a git repo, so there is no commit
    assert scanner.scan_results[0][RESULT_KEY_COMMIT] is None
    assert scanner.scan_results[0][RESULT_KEY_RULE] == 'rule_1'
    assert scanner.scan_results[0][RESULT_KEY_STRINGS] == [(0, '$', b'test_rule_1')]
    assert scanner.scan_results[0][RESULT_KEY_TAGS] == ['tag_1']

@pytest.mark.integration
def test_yara_rule_blacklisting(scanner):
    assert scanner.scan_data('test_rule_1')
    scanner.blacklist_rule('rule_1')
    scanner.load_rules()
    assert not scanner.scan_data('test_rule_1')

@pytest.mark.integration
def test_compiled_file_tracking(shared_datadir):
    target_file = str(shared_datadir / 'signatures' / 'compiled.cyar')
    scanner = YaraScanner()
    scanner.track_compiled_yara_file(target_file)

    sample_data = str(shared_datadir / 'scan_targets' / 'scan_target_1.txt')
    # file does not exist yet
    with pytest.raises(RulesNotLoadedError):
        scanner.scan(sample_data)

    # load a yara rule, compile and save compilation
    source_rule = str(shared_datadir / 'signatures' / 'ruleset_a' / 'rule_1.yar')
    temp = YaraScanner()
    temp.track_yara_file(source_rule)
    temp.load_rules()
    temp.save_compiled_rules(target_file)
    assert os.path.exists(target_file)

    # rules now exists so this should match
    assert scanner.check_rules()
    assert scanner.scan(sample_data)

    # recompile with a different rule
    time.sleep(0.01) # XXX depending on the mtime not super precise
    source_rule = str(shared_datadir / 'signatures' / 'ruleset_b' / 'rule_1.yar')
    temp = YaraScanner()
    temp.track_yara_file(source_rule)
    temp.load_rules()
    temp.save_compiled_rules(target_file)
    assert os.path.exists(target_file)

    assert scanner.check_rules()
    scanner.load_rules()

    # the rule changed so this should NOT match
    assert not scanner.scan(sample_data)

    # recompile again with the original rule
    time.sleep(0.01) # XXX depending on the mtime not super precise
    source_rule = str(shared_datadir / 'signatures' / 'ruleset_a' / 'rule_1.yar')
    temp = YaraScanner()
    temp.track_yara_file(source_rule)
    temp.load_rules()
    temp.save_compiled_rules(target_file)
    assert os.path.exists(target_file)

    assert scanner.check_rules()
    scanner.load_rules()
    assert scanner.scan(sample_data)

    # delete the compiled rule file
    os.remove(target_file)

    assert not scanner.check_rules()
    scanner.load_rules()
    # should still be ok
    assert scanner.scan(sample_data)

@pytest.mark.integration
def test_auto_compile(shared_datadir, tmpdir, caplog):
    caplog.set_level(logging.DEBUG)
    compiled_rules_dir = tmpdir.mkdir('compiled_rules')
    scanner = YaraScanner(
            signature_dir=str(shared_datadir / 'signatures'), 
            auto_compile_rules=True, 
            auto_compiled_rules_dir=compiled_rules_dir)

    scanner.load_rules()
    # there should be a single .cyar file in tempdir
    file_list = os.listdir(compiled_rules_dir)
    assert len(file_list) == 1
    assert file_list[0].endswith('.cyar')

    scanner = YaraScanner(
            signature_dir=str(shared_datadir / 'signatures'), 
            auto_compile_rules=True, 
            auto_compiled_rules_dir=compiled_rules_dir)

    # make sure the compiled rules were used
    scanner.load_rules()
    assert 'up to date compiled rules already exist at' in caplog.text

@pytest.mark.integration
def test_single_file_tracking(scanner, shared_datadir):
    scanner = YaraScanner()
    yara_rule_path = str(shared_datadir / 'signatures' / 'ruleset_a' / 'rule_1.yar')
    scanner.track_yara_file(yara_rule_path)
    scanner.load_rules()
    assert not scanner.check_rules()
    assert scanner.tracked_files
    assert yara_rule_path in scanner.tracked_files
    with open(yara_rule_path, 'a') as fp:
        fp.write('\n//test')

    # this should return True after the file has been modified
    assert scanner.check_rules()
    scanner.load_rules()
    assert not scanner.check_rules()
    with open(yara_rule_path, 'r') as fp:
        rule_content = fp.read()

    os.remove(yara_rule_path)
    assert scanner.check_rules()
    assert scanner.tracked_files[yara_rule_path] is None
    assert scanner.load_rules()

    with open(yara_rule_path, 'w') as fp:
        fp.write(rule_content)

    assert scanner.check_rules()
    assert scanner.load_rules()

@pytest.mark.integration
def test_dir_tracking(shared_datadir):
    s = YaraScanner()
    yara_dir_path = str(shared_datadir / 'signatures' / 'ruleset_a')
    yara_rule_path = str(shared_datadir / 'signatures' / 'ruleset_a' / 'rule_1.yar')
    s.track_yara_dir(yara_dir_path)
    s.load_rules()
    assert not s.check_rules()
    assert s.tracked_dirs
    assert len(s.tracked_dirs[yara_dir_path]) == 1
    
    with open(yara_rule_path, 'a') as fp:
        fp.write('\ntest')

    # this should return True after the file has been modified
    assert s.check_rules()
    s.load_rules()
    assert not s.check_rules()
    
    os.remove(yara_rule_path)

    # this should return True after the file has been deleted
    assert s.check_rules()
    # when files are deleted from a tracked dir they are removed from the dict tracking
    assert not s.tracked_dirs[yara_dir_path]
    assert not s.load_rules()

    # test when a new rule is loaded
    new_yara_rule_path = str(shared_datadir / 'signatures' / 'ruleset_a' / 'new_rule.yar')
    with open(new_yara_rule_path, 'w') as fp:
        fp.write("""
    rule test_add_rule {
        strings:
            $ = "whatever"
        condition:
            all of them
    }
        """)

    assert s.check_rules()
    assert s.load_rules()
    assert len(s.tracked_dirs[yara_dir_path]) == 1

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_repo_tracking(repo):
    s = YaraScanner()
    s.track_yara_repository(repo)
    assert s.check_rules()
    assert s.load_rules()
    assert not s.check_rules()
    with open(os.path.join(repo, 'rule_1.yar'), 'a') as fp:
        fp.write('\n// modified')
    
    # not considered modified until changes committed to repo
    assert not s.check_rules()
    Popen(['git', '-C', repo, 'add', '*.yar']).wait()
    Popen(['git', '-C', repo, 'commit', '-m', 'modified']).wait()
    assert s.check_rules()
    assert s.load_rules()
    assert not s.check_rules()

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_repo_commit_in_scan_results(repo):
    s = YaraScanner()
    s.track_yara_repository(repo)
    assert s.load_rules()
    # matches ruleset_a/rule_1.yar which came from the git repo
    assert s.scan_data('test_rule_1')
    assert s.scan_results[0][RESULT_KEY_COMMIT] == get_current_repo_commit(repo)

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_signature_dir_git_repo_dirs(repo, shared_datadir):
    signature_dir = str(shared_datadir / 'signatures')
    repo_dir = str(shared_datadir / 'signatures' / 'ruleset_a')
    plain_dir = str(shared_datadir / 'signatures' / 'ruleset_b')

    # the caller says which directories are part of a git repository
    s = YaraScanner(signature_dir=signature_dir, git_repo_dirs=['ruleset_a'])
    assert list(s.tracked_repos.keys()) == [repo_dir]
    assert s.tracked_repos[repo_dir] == get_current_repo_commit(repo)
    assert list(s.tracked_dirs.keys()) == [plain_dir]

    # entries can also be paths instead of names
    s = YaraScanner(signature_dir=signature_dir, git_repo_dirs=[repo_dir])
    assert list(s.tracked_repos.keys()) == [repo_dir]
    assert list(s.tracked_dirs.keys()) == [plain_dir]

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_signature_dir_no_git_repo_autodetection(repo, shared_datadir):
    # ruleset_a is a git repository but the caller did not say so, so it is
    # tracked as a plain directory
    s = YaraScanner(signature_dir=str(shared_datadir / 'signatures'))
    assert not s.tracked_repos
    assert len(s.tracked_dirs) == 2
    assert s.load_rules()
    assert s.scan_data('test_rule_1')
    assert s.scan_results[0][RESULT_KEY_COMMIT] is None

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_track_subdirectory_of_repo(parent_repo):
    ruleset_dir = os.path.join(parent_repo, 'signatures', 'ruleset_a')
    # the rule directory is inside the repository but has no .git of its own
    assert not os.path.exists(os.path.join(ruleset_dir, '.git'))

    s = YaraScanner()
    assert s.track_yara_repository(ruleset_dir) is not False
    assert s.tracked_repos[ruleset_dir] == get_current_repo_commit(parent_repo)
    assert s.load_rules()
    assert s.scan_data('test_rule_1')
    assert s.scan_results[0][RESULT_KEY_COMMIT] == get_current_repo_commit(parent_repo)

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_signature_dir_subdirectory_of_repo(parent_repo):
    signature_dir = os.path.join(parent_repo, 'signatures')
    ruleset_dir = os.path.join(signature_dir, 'ruleset_a')

    s = YaraScanner(signature_dir=signature_dir, git_repo_dirs=['ruleset_a'])
    assert s.tracked_repos[ruleset_dir] == get_current_repo_commit(parent_repo)
    assert s.load_rules()
    assert s.scan_data('test_rule_1')
    assert s.scan_results[0][RESULT_KEY_COMMIT] == get_current_repo_commit(parent_repo)

@pytest.mark.integration
@pytest.mark.skipif(not shutil.which('git'), reason="missing git in PATH")
def test_track_yara_repository_non_repo(tmp_path):
    # a directory that is not part of any git repository is still rejected
    yara_dir = tmp_path / 'not_a_repo'
    create_file(str(yara_dir / 'rule_1.yar'), 'rule rule_1 { condition: true }')

    s = YaraScanner()
    assert s.track_yara_repository(str(yara_dir)) is False
    assert not s.tracked_repos

@pytest.mark.integration
def test_git_repo_dirs_unknown_entry(shared_datadir, caplog):
    signature_dir = str(shared_datadir / 'signatures')
    with caplog.at_level(logging.WARNING, logger='yara-scanner'):
        s = YaraScanner(signature_dir=signature_dir, git_repo_dirs=['ruleset_missing'])

    assert not s.tracked_repos
    assert len(s.tracked_dirs) == 2
    assert 'ruleset_missing' in caplog.text

#region meta_rule_tests
meta_rule_tests = [
    ("""
rule test_meta_filename {
meta:
    file_name = "scan_target_1.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_multi {
meta:
    file_name = "scan_target_1.txt,scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_not {
meta:
    file_name = "!scan_target_1.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_filename_not_multi {
meta:
    file_name = "!scan_target_1.txt,scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_2.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_filename_not_multi {
meta:
    file_name = "!scan_target_1.txt,scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_3.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_sub {
meta:
    file_name = "sub:scan_target_1."
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_re {
meta:
    file_name = "re:^scan_target_1"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filename_re {
meta:
    file_name = "re:^scan_target_1"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_2.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_filename_re {
meta:
    file_name = "!re:^scan_target_1"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'scan_target_2.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filepath_sub {
meta:
    full_path = "sub:data/scan_target_1.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filepath_sub_multi {
meta:
    full_path = "sub:data/scan_target_1.txt,data/scan_target_2.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_2.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_filepath_re {
meta:
    full_path = "re:data/scan_target_[0-9]+.txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_fileext {
meta:
    file_ext = "txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_fileext_multi {
meta:
    file_ext = "txt,pdf,doc"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.doc', 
    'Sample content.',
    True),
    ("""
rule test_meta_mime {
meta:
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_mime_multi {
meta:
    mime_type = "text/plain,text/html"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_mime {
meta:
    mime_type = "re:^text/.+"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    True),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_2.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "!scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_1.txt', 
    'Sample content.',
    False),
    ("""
rule test_meta_multi_meta {
meta:
    file_name = "!scan_target_1.txt"
    mime_type = "text/plain"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """, 
    'data/scan_target_2.txt', 
    'Sample content.',
    True),
]
#endregion

@pytest.mark.integration
@pytest.mark.parametrize("yara_rule_content, scan_target_name, scan_target_content, expected", meta_rule_tests)
def test_meta_directives(tmp_path, yara_rule_content, scan_target_name, scan_target_content, expected):
    scanner = YaraScanner()
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), yara_rule_content)
    scan_target_path = create_file(str(tmp_path / scan_target_name), scan_target_content)
    scanner.track_yara_file(yara_rule_path)
    scanner.load_rules()

    if expected:
        assert scanner.scan(scan_target_path)
        assert len(scanner.scan_results) == 1
    else:
        assert not scanner.scan(scan_target_path)
        assert len(scanner.scan_results) == 0

#region meta_tags_tests
meta_tags_tests = [
    # (rule, filename, content, caller_meta_tags, expected)

    # exact match - match
    ("""
rule test_meta_tags_exact {
meta:
    meta_tags = "email_attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["email_attachment"],
    True),

    # exact match - no match
    ("""
rule test_meta_tags_exact_nomatch {
meta:
    meta_tags = "email_attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["web_download"],
    False),

    # no tags provided (None) - non-inverted rule should skip
    ("""
rule test_meta_tags_none {
meta:
    meta_tags = "email_attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    None,
    False),

    # no tags provided (empty list) - non-inverted rule should skip
    ("""
rule test_meta_tags_empty {
meta:
    meta_tags = "email_attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    [],
    False),

    # comma-separated OR - one matches
    ("""
rule test_meta_tags_csv {
meta:
    meta_tags = "email_attachment,web_download"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["web_download"],
    True),

    # negation - tag present -> skip
    ("""
rule test_meta_tags_negated {
meta:
    meta_tags = "!trusted"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["trusted"],
    False),

    # negation - tag NOT present -> don't skip
    ("""
rule test_meta_tags_negated_nomatch {
meta:
    meta_tags = "!trusted"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["suspicious"],
    True),

    # negation with no tags provided -> should match (NOT X with no tags = don't skip)
    ("""
rule test_meta_tags_negated_none {
meta:
    meta_tags = "!trusted"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    None,
    True),

    # regex match
    ("""
rule test_meta_tags_regex {
meta:
    meta_tags = "re:^email_"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["email_attachment"],
    True),

    # regex no match
    ("""
rule test_meta_tags_regex_nomatch {
meta:
    meta_tags = "re:^email_"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["web_download"],
    False),

    # substring match
    ("""
rule test_meta_tags_sub {
meta:
    meta_tags = "sub:attach"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["email_attachment"],
    True),

    # negated regex
    ("""
rule test_meta_tags_negated_regex {
meta:
    meta_tags = "!re:^trusted"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["trusted_source"],
    False),

    # negated regex - no match on regex -> rule applies
    ("""
rule test_meta_tags_negated_regex_pass {
meta:
    meta_tags = "!re:^trusted"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["suspicious"],
    True),

    # multiple caller tags - one matches
    ("""
rule test_meta_tags_multi_caller {
meta:
    meta_tags = "email_attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["web_download", "email_attachment"],
    True),

    # case insensitivity
    ("""
rule test_meta_tags_case {
meta:
    meta_tags = "Email_Attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["email_attachment"],
    True),

    # combined with file_ext - both match
    ("""
rule test_meta_tags_combined {
meta:
    meta_tags = "email_attachment"
    file_ext = "txt"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["email_attachment"],
    True),

    # combined with file_ext - meta_tags matches but file_ext doesn't
    ("""
rule test_meta_tags_combined_fail {
meta:
    meta_tags = "email_attachment"
    file_ext = "pdf"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """,
    'target.txt',
    'Sample content.',
    ["email_attachment"],
    False),
]
#endregion

@pytest.mark.integration
@pytest.mark.parametrize("yara_rule_content, scan_target_name, scan_target_content, caller_meta_tags, expected", meta_tags_tests)
def test_meta_tags_directive(tmp_path, yara_rule_content, scan_target_name, scan_target_content, caller_meta_tags, expected):
    scanner = YaraScanner()
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), yara_rule_content)
    scan_target_path = create_file(str(tmp_path / scan_target_name), scan_target_content)
    scanner.track_yara_file(yara_rule_path)
    scanner.load_rules()

    if expected:
        assert scanner.scan(scan_target_path, meta_tags=caller_meta_tags)
        assert len(scanner.scan_results) == 1
    else:
        assert not scanner.scan(scan_target_path, meta_tags=caller_meta_tags)
        assert len(scanner.scan_results) == 0

@pytest.mark.integration
def test_meta_tags_scan_data(tmp_path):
    """Test that meta_tags works with scan_data() as well."""
    rule_content = """
rule test_meta_tags_data {
meta:
    meta_tags = "email_attachment"
strings:
    $ = "Sample content."
condition:
    all of them
}
    """
    scanner = YaraScanner()
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), rule_content)
    scanner.track_yara_file(yara_rule_path)
    scanner.load_rules()

    # with matching tag
    assert scanner.scan_data('Sample content.', meta_tags=["email_attachment"])
    assert len(scanner.scan_results) == 1

    # without matching tag
    assert not scanner.scan_data('Sample content.', meta_tags=["web_download"])
    assert len(scanner.scan_results) == 0

    # with no tags
    assert not scanner.scan_data('Sample content.', meta_tags=None)
    assert len(scanner.scan_results) == 0

@pytest.mark.integration
def test_rules_changed_without_loading(tmp_path):
    """rules_changed() reports source changes only, so rules can be watched without compiling them."""
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), 'rule a { condition: true }')
    scanner = YaraScanner()
    scanner.track_yara_file(yara_rule_path)

    # never loaded: check_rules() wants a load, rules_changed() sees no change
    assert scanner.check_rules()
    assert not scanner.rules_changed()
    assert scanner.rules is None

    os.utime(yara_rule_path, (time.time() + 10, time.time() + 10))
    assert scanner.rules_changed()
    # the change was tracked, so it is reported once
    assert not scanner.rules_changed()
    assert scanner.rules is None

@pytest.mark.integration
def test_scan_does_not_modify_external_vars(tmp_path):
    yara_rule_path = create_file(str(tmp_path / 'rule.yar'), 'rule a { strings: $ = "Sample" condition: all of them }')
    scan_target_path = create_file(str(tmp_path / 'target.txt'), 'Sample content.')
    scanner = YaraScanner()
    scanner.track_yara_file(yara_rule_path)
    scanner.load_rules()

    external_vars = {"filetype": "text"}
    assert scanner.scan(scan_target_path, external_vars=external_vars, meta_tags=["email_attachment"])
    assert scanner.scan_data('Sample content.', external_vars=external_vars, meta_tags=["email_attachment"])
    assert external_vars == {"filetype": "text"}

@pytest.mark.integration
def test_compiled_sources(tmp_path, caplog):
    """Each file read is recorded with its namespace, its text, its rules and its warnings, and a
    file that does not compile with its error."""
    rules_dir = tmp_path / 'rules'
    good = create_file(str(rules_dir / 'good.yar'), 'rule good { strings: $a = { 00 } condition: $a }')
    bad = create_file(str(rules_dir / 'bad.yar'), 'rule bad { condition: nope }')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert not scanner.load_rules()

    records = {record.path: record for record in scanner.compiled_sources}
    assert set(records) == {good, bad}
    assert records[good] == CompiledSource(
        good, str(rules_dir), 'rule good { strings: $a = { 00 } condition: $a }',
        warnings=['line 1: string "$a" may slow down scanning'], rules=['good'])
    assert records[bad].namespace == str(rules_dir)
    assert records[bad].source == 'rule bad { condition: nope }'
    assert 'undefined identifier "nope"' in records[bad].error
    assert records[bad].rules == []
    assert scanner.compile_error is None
    # the file that did not compile is left out of the rules
    assert [rule.identifier for rule in scanner.rules] == ['good']

@pytest.mark.integration
def test_compiled_sources_includes(tmp_path):
    """Includes are recorded on the file that pulled them in, with the text compiled in their place."""
    rules_dir = tmp_path / 'rules'
    top = create_file(str(rules_dir / 'top.yar'),
                      'include "inc/inner.yara.inc"\ninclude "leaf.yara.inc"\nrule top { condition: inner and leaf }')
    create_file(str(rules_dir / 'inc' / 'inner.yara.inc'), 'rule inner { condition: true }')
    create_file(str(rules_dir / 'leaf.yara.inc'), 'rule leaf { condition: true }')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert scanner.load_rules()

    (record,) = scanner.compiled_sources
    assert record.path == top
    assert record.includes == [
        IncludedSource('inc/inner.yara.inc', str(rules_dir / 'inc' / 'inner.yara.inc'), 'rule inner { condition: true }'),
        IncludedSource('leaf.yara.inc', str(rules_dir / 'leaf.yara.inc'), 'rule leaf { condition: true }'),
    ]
    assert sorted(record.rules) == ['inner', 'leaf', 'top']
    assert scanner.scan_data('x')
    assert {result['rule'] for result in scanner.scan_results} == {'inner', 'leaf', 'top'}

@pytest.mark.integration
def test_compiled_sources_include_not_readable(tmp_path, caplog):
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'top.yar'), 'include "missing.yara.inc"\nrule top { condition: true }')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert scanner.load_rules()

    (include,) = scanner.compiled_sources[0].includes
    assert include.name == 'missing.yara.inc'
    assert include.path == str(rules_dir / 'missing.yara.inc')
    assert include.source == ''
    assert 'No such file or directory' in include.error
    assert any(record.levelno == logging.ERROR and 'unable to include file' in record.getMessage()
               for record in caplog.records)

@pytest.mark.integration
def test_compiled_sources_include_changed_while_compiling(tmp_path, monkeypatch):
    """The rules are compiled from the include text that was recorded, even when the file changes
    between compiling each file on its own and compiling them together."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'top.yar'), 'include "inc.yara.inc"\nrule top { condition: true }')
    include_path = create_file(str(rules_dir / 'inc.yara.inc'), 'rule before { condition: true }')
    real_compile = yara.compile

    def compile(*args, **kwargs):
        if 'sources' in kwargs:
            create_file(include_path, 'rule after { condition: true }')
        return real_compile(*args, **kwargs)

    monkeypatch.setattr(yara, 'compile', compile)
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert scanner.load_rules()

    assert scanner.compiled_sources[0].includes[0].source == 'rule before { condition: true }'
    assert sorted(rule.identifier for rule in scanner.rules) == ['before', 'top']

@pytest.mark.integration
def test_compiled_sources_include_from_tracked_file(tmp_path):
    """A tracked file's namespace is its own path, which the combined compile used to resolve its
    includes against; it now gets the include its file compiled with on its own."""
    rule_path = create_file(str(tmp_path / 'top.yar'), 'include "inc.yara.inc"\nrule top { condition: inc }')
    create_file(str(tmp_path / 'inc.yara.inc'), 'rule inc { condition: true }')
    scanner = YaraScanner()
    scanner.track_yara_file(rule_path)

    assert scanner.load_rules()

    assert scanner.compile_error is None
    assert sorted(rule.identifier for rule in scanner.rules) == ['inc', 'top']

@pytest.mark.integration
def test_compiled_sources_include_not_read_alone(tmp_path, monkeypatch, caplog):
    """An include the combined compile asks for that no file asked for on its own is read then, and
    logged."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'top.yar'), 'rule top { condition: true }')
    create_file(str(rules_dir / 'extra.yara.inc'), 'rule extra { condition: true }')
    real_compile = yara.compile

    def compile(*args, **kwargs):
        if 'sources' in kwargs:
            kwargs['sources'] = {ns: source + '\ninclude "extra.yara.inc"' for ns, source in kwargs['sources'].items()}
        return real_compile(*args, **kwargs)

    monkeypatch.setattr(yara, 'compile', compile)
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert scanner.load_rules()

    assert sorted(rule.identifier for rule in scanner.rules) == ['extra', 'top']
    assert any(record.levelno == logging.WARNING and 'was not read when its file compiled on its own' in record.getMessage()
               for record in caplog.records)

@pytest.mark.integration
def test_compile_error(tmp_path, caplog):
    """Files that compile on their own but not together: the error is kept, and so is the record."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'a.yar'), 'rule same { condition: true }')
    create_file(str(rules_dir / 'b.yar'), 'rule same { condition: false }')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert not scanner.load_rules()

    assert scanner.rules is None
    assert 'duplicated identifier "same"' in scanner.compile_error
    assert sorted(os.path.basename(record.path) for record in scanner.compiled_sources) == ['a.yar', 'b.yar']
    assert all(record.error is None for record in scanner.compiled_sources)

    # a later load that succeeds clears both
    create_file(str(rules_dir / 'b.yar'), 'rule other { condition: false }')
    assert scanner.load_rules()
    assert scanner.compile_error is None
    assert sorted(record.rules[0] for record in scanner.compiled_sources) == ['other', 'same']

@pytest.mark.integration
def test_compiled_sources_cleared_by_compiled_rules(tmp_path):
    """Rules loaded from a compiled file come with no sources."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'a.yar'), 'rule a { condition: true }')
    scanner = YaraScanner(auto_compile_rules=True, auto_compiled_rules_dir=str(tmp_path))
    scanner.track_yara_dir(str(rules_dir))
    assert scanner.load_rules()
    assert len(scanner.compiled_sources) == 1

    # the second load finds the rules the first one saved
    assert scanner.load_rules()
    assert scanner.compiled_sources == []

@pytest.mark.integration
def test_nested_includes(tmp_path, monkeypatch):
    """A nested include is relative to the file that has the include statement, in both passes and
    whatever the working directory is."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'top.yar'), 'include "inc/inner.inc"\nrule top { condition: inner and leaf and sibling }')
    create_file(str(rules_dir / 'inc' / 'inner.inc'),
                'include "deeper/leaf.inc"\ninclude "sibling.inc"\nrule inner { condition: true }')
    create_file(str(rules_dir / 'inc' / 'deeper' / 'leaf.inc'), 'rule leaf { condition: true }')
    create_file(str(rules_dir / 'inc' / 'sibling.inc'), 'rule sibling { condition: true }')
    # where the include used to resolve in the combined compile
    create_file(str(rules_dir / 'deeper' / 'leaf.inc'), 'rule wrong_leaf { condition: true }')
    create_file(str(rules_dir / 'sibling.inc'), 'rule wrong_sibling { condition: true }')
    monkeypatch.chdir(tmp_path)
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert scanner.load_rules()

    assert [(include.name, include.path, include.error) for include in scanner.compiled_sources[0].includes] == [
        ('inc/inner.inc', str(rules_dir / 'inc' / 'inner.inc'), None),
        ('deeper/leaf.inc', str(rules_dir / 'inc' / 'deeper' / 'leaf.inc'), None),
        ('sibling.inc', str(rules_dir / 'inc' / 'sibling.inc'), None),
    ]
    assert sorted(rule.identifier for rule in scanner.rules) == ['inner', 'leaf', 'sibling', 'top']

@pytest.mark.integration
def test_nested_includes_same_parent_name(tmp_path):
    """Nested includes whose parents were requested by the same name, from different directories,
    each resolve against their own parent."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'top.yar'), 'include "a/p.inc"\ninclude "b/p.inc"\nrule top { condition: true }')
    for name in ('a', 'b'):
        create_file(str(rules_dir / name / 'p.inc'), 'include "x.inc"')
        create_file(str(rules_dir / name / 'x.inc'), 'include "y.inc"')
        create_file(str(rules_dir / name / 'y.inc'), f'rule {name}_y {{ condition: true }}')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert scanner.load_rules()

    assert [include.path for include in scanner.compiled_sources[0].includes if include.name == 'y.inc'] == [
        str(rules_dir / 'a' / 'y.inc'), str(rules_dir / 'b' / 'y.inc')]
    assert sorted(rule.identifier for rule in scanner.rules) == ['a_y', 'b_y', 'top']

@pytest.mark.integration
def test_rule_file_not_utf8(tmp_path, caplog):
    """A rule file that cannot be decoded is left out with its error, and the rest are loaded."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'good.yar'), 'rule good { condition: true }')
    bad = str(rules_dir / 'bad.yar')
    with open(bad, 'wb') as fp:
        fp.write(b'rule bad { strings: $a = "\xff\xfe" condition: $a }')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert not scanner.load_rules()

    assert [rule.identifier for rule in scanner.rules] == ['good']
    (record,) = [record for record in scanner.compiled_sources if record.path == bad]
    assert record.source == ''
    assert "can't decode byte 0xff" in record.error
    assert any(record.levelno == logging.ERROR and f'unable to read {bad}' in record.getMessage()
               for record in caplog.records)

@pytest.mark.integration
def test_rule_file_not_readable(tmp_path, caplog):
    """A tracked path that cannot be read (here a directory named like a rule file) is left out
    with its error, and the rest are loaded."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'good.yar'), 'rule good { condition: true }')
    os.makedirs(str(rules_dir / 'dir.yar'))
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))

    assert not scanner.load_rules()

    assert [rule.identifier for rule in scanner.rules] == ['good']
    (record,) = [record for record in scanner.compiled_sources if record.path.endswith('dir.yar')]
    assert 'Is a directory' in record.error
    assert any(record.levelno == logging.ERROR and 'unable to read' in record.getMessage()
               for record in caplog.records)

@pytest.mark.integration
def test_rule_file_removed(tmp_path):
    """A tracked file that is gone when the rules are loaded is skipped, and is not an error."""
    rules_dir = tmp_path / 'rules'
    create_file(str(rules_dir / 'good.yar'), 'rule good { condition: true }')
    gone = create_file(str(rules_dir / 'gone.yar'), 'rule gone { condition: true }')
    scanner = YaraScanner()
    scanner.track_yara_dir(str(rules_dir))
    os.remove(gone)

    assert scanner.load_rules()

    assert [rule.identifier for rule in scanner.rules] == ['good']
    assert [record.path for record in scanner.compiled_sources] == [str(rules_dir / 'good.yar')]
