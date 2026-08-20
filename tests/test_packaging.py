"""Packaging tests -- the RC-22 class, not the RC-22 instance.

RC-22 was `defusedxml`: imported by `reconkg/importers.py` behind a
try/except, declared nowhere. On a clean checkout the except branch ran, and
until cycle 8 that branch rejected 100% of genuine nmap output. The whole
suite stayed green because nothing anywhere compared *what the code imports*
against *what the project says it needs*.

That comparison is what this module does. `test_every_third_party_import_is_
declared` walks the AST of every file under `reconkg/`, collects top-level
import roots, subtracts `sys.stdlib_module_names` and first-party names, and
diffs the remainder against `[project].dependencies` in pyproject.toml. Adding
an undeclared import to any module under `reconkg/` fails this test by name.

Deliberately AST-based rather than import-based: importing the modules would
only reveal dependencies that happen to be installed in the test environment,
which is precisely the environment where RC-22 hid. Static analysis sees the
`defusedxml` import whether or not defusedxml is present.

`test_detector_catches_a_removed_declaration` is the test-for-the-test: it
feeds the checker a pyproject with defusedxml deleted and asserts the failure
names the offending module. Without it, a checker that silently found nothing
would look identical to a clean tree.
"""

from __future__ import annotations

import ast
import re
import sys
from pathlib import Path

import pytest

try:  # 3.11+ ships tomllib; 3.10 is in the support matrix and does not.
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - interpreter-dependent
    import tomli as tomllib

REPO_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_DIR = REPO_ROOT / "reconkg"
PYPROJECT = REPO_ROOT / "pyproject.toml"
REQUIREMENTS = REPO_ROOT / "requirements.txt"
REQUIREMENTS_DEV = REPO_ROOT / "requirements-dev.txt"

#  Import name -> distribution name, for the cases where they differ. Kept
#  explicit rather than resolved through importlib.metadata: metadata lookup
#  only works for packages that are installed, and an undeclared dependency is
#  frequently one that is not.
IMPORT_TO_DISTRIBUTION = {
    "defusedxml": "defusedxml",
    "fastapi": "fastapi",
    "pydantic": "pydantic",
    "uvicorn": "uvicorn",
    "httpx": "httpx",
    "websockets": "websockets",
    "starlette": "starlette",
    #  stdlib from 3.11, a PyPI backport on 3.10. `sys.stdlib_module_names`
    #  is interpreter-specific, so on 3.10 this reads as third party -- which
    #  is correct: on 3.10 it must be installed.
    "tomllib": "tomli",
    "yaml": "pyyaml",
    "dotenv": "python-dotenv",
    "jose": "python-jose",
    "dateutil": "python-dateutil",
    "OpenSSL": "pyopenssl",
}

FIRST_PARTY = {"reconkg", "audit", "tests"}

_REQUIREMENT_NAME = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)")


def canonical(name: str) -> str:
    """PEP 503 normalisation, so `pytest_asyncio` == `pytest-asyncio`."""
    return re.sub(r"[-_.]+", "-", name).lower()


def requirement_name(spec: str) -> str:
    match = _REQUIREMENT_NAME.match(spec)
    assert match is not None, f"unparseable requirement: {spec!r}"
    return canonical(match.group(1))


def requirement_constraint(spec: str) -> str:
    """The version constraint with the name, extras and marker stripped."""
    body = spec.split(";", 1)[0]
    body = re.sub(r"^\s*[A-Za-z0-9][A-Za-z0-9._-]*\s*(\[[^\]]*\])?", "", body)
    return body.replace(" ", "")


def load_pyproject(text: str | None = None) -> dict:
    if text is None:
        return tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    return tomllib.loads(text)


def declared_distributions(pyproject: dict, *, include_dev: bool = False):
    """Canonical distribution names declared in pyproject."""
    specs = list(pyproject["project"].get("dependencies", []))
    if include_dev:
        extras = pyproject["project"].get("optional-dependencies", {})
        for group in extras.values():
            specs.extend(group)
    return {requirement_name(spec) for spec in specs}


def python_sources(root: Path) -> list[Path]:
    return sorted(p for p in root.rglob("*.py")
                  if "__pycache__" not in p.parts)


def top_level_imports(path: Path) -> set[str]:
    """Root module names imported anywhere in `path`, relative ones excluded.

    `ast.walk` rather than a scan of module-level statements: the RC-22 import
    lived inside a `try:` block, and dependencies also hide inside functions
    and `if TYPE_CHECKING:` guards.
    """
    tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                found.add(alias.name.split(".")[0])
        elif isinstance(node, ast.ImportFrom):
            if node.level:          # relative import -- first party
                continue
            if node.module:
                found.add(node.module.split(".")[0])
    return found


def third_party_imports(root: Path) -> dict[str, set[Path]]:
    """Map third-party import root -> the files that import it."""
    result: dict[str, set[Path]] = {}
    for path in python_sources(root):
        for name in top_level_imports(path):
            if name in sys.stdlib_module_names or name in FIRST_PARTY:
                continue
            if name.startswith("_"):        # _typeshed and friends
                continue
            result.setdefault(name, set()).add(path)
    return result


def undeclared_imports(pyproject: dict) -> dict[str, set[Path]]:
    declared = declared_distributions(pyproject)
    offenders = {}
    for name, files in third_party_imports(PACKAGE_DIR).items():
        dist = canonical(IMPORT_TO_DISTRIBUTION.get(name, name))
        if dist not in declared:
            offenders[name] = files
    return offenders


def parse_requirements(path: Path) -> dict[str, str]:
    """name -> constraint, ignoring comments, blanks and `-r` includes."""
    parsed: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        parsed[requirement_name(line)] = requirement_constraint(line)
    return parsed


# --------------------------------------------------------------------------
# the RC-22 test
# --------------------------------------------------------------------------

def test_every_third_party_import_is_declared():
    offenders = undeclared_imports(load_pyproject())
    if offenders:
        detail = "; ".join(
            f"{name} (imported by "
            f"{', '.join(sorted(p.name for p in files))})"
            for name, files in sorted(offenders.items()))
        pytest.fail(
            f"undeclared third-party dependency: {detail}. "
            f"Add it to [project].dependencies in pyproject.toml -- an "
            f"import you never declare is RC-22 waiting for a clean checkout.")


def test_detector_catches_a_removed_declaration():
    """The test-for-the-test: delete defusedxml, expect it named."""
    text = PYPROJECT.read_text(encoding="utf-8")
    doctored = re.sub(r'^\s*"defusedxml[^"]*",\n', "", text, flags=re.M)
    assert doctored != text, "defusedxml is no longer declared literally"

    offenders = undeclared_imports(load_pyproject(doctored))
    assert "defusedxml" in offenders, (
        "removing the defusedxml declaration did not trip the checker; the "
        "drift test is inert")
    assert any(p.name == "importers.py" for p in offenders["defusedxml"])


def test_defusedxml_is_declared_not_merely_optional():
    """RC-22 itself, pinned.

    `importers.py` falls back to the stdlib parser when defusedxml is absent.
    The fallback must never be the path a fresh install takes, so the
    dependency is unconditional -- no extras group, no environment marker.
    """
    declared = load_pyproject()["project"]["dependencies"]
    matches = [s for s in declared if requirement_name(s) == "defusedxml"]
    assert matches, "defusedxml missing from [project].dependencies"
    assert ";" not in matches[0], (
        f"defusedxml is conditional ({matches[0]!r}); it must be "
        f"unconditional or the fallback parser ships by default")


def test_detector_sees_the_imports_known_to_exist():
    """Guards the detector against silently seeing nothing.

    If a refactor made `third_party_imports` return an empty set, every other
    test in this module would still pass. A subset assertion rather than
    equality: a new *declared* dependency is legitimate and should not fail
    here, but these three must always be visible to the walker.
    """
    found = set(third_party_imports(PACKAGE_DIR))
    expected = {"defusedxml", "fastapi", "pydantic"}
    assert expected <= found, (
        f"import walker lost sight of {sorted(expected - found)}; it found "
        f"{sorted(found)}. The drift detector is not reading the package.")


# --------------------------------------------------------------------------
# version and requirements agreement
# --------------------------------------------------------------------------

def test_pyproject_version_matches_package_version():
    import reconkg
    declared = load_pyproject()["project"]["version"]
    assert declared == reconkg.__version__, (
        f"pyproject version {declared!r} != reconkg.__version__ "
        f"{reconkg.__version__!r}")


def test_pyproject_name_and_python_requirement():
    project = load_pyproject()["project"]
    assert project["name"] == "reconkg"
    assert project["requires-python"] == ">=3.10"


def test_requirements_txt_agrees_with_pyproject():
    pyproject = load_pyproject()
    runtime = {requirement_name(s): requirement_constraint(s)
               for s in pyproject["project"]["dependencies"]}
    requirements = parse_requirements(REQUIREMENTS)

    missing = sorted(set(runtime) - set(requirements))
    extra = sorted(set(requirements) - set(runtime))
    assert not missing, (
        f"declared in pyproject but absent from requirements.txt: {missing}")
    assert not extra, (
        f"in requirements.txt but not declared in pyproject: {extra}")

    for name in sorted(runtime):
        assert runtime[name] == requirements[name], (
            f"version constraint for {name} disagrees: pyproject "
            f"{runtime[name]!r} vs requirements.txt {requirements[name]!r}")


def test_requirements_dev_agrees_with_dev_extra():
    pyproject = load_pyproject()
    dev = pyproject["project"]["optional-dependencies"]["dev"]
    extra_names = {requirement_name(s) for s in dev}
    file_names = set(parse_requirements(REQUIREMENTS_DEV))
    assert file_names == extra_names, (
        f"requirements-dev.txt {sorted(file_names)} disagrees with the "
        f"[dev] extra {sorted(extra_names)}")


def test_dev_extra_covers_what_the_tests_import():
    """Test-only imports need declaring too -- CI installs `.[dev]`, not more.

    Same failure mode as RC-22, one directory over: a test that imports httpx
    and a project that never declares it passes locally and fails on a clean
    runner.
    """
    declared = declared_distributions(load_pyproject(), include_dev=True)
    offenders = {}
    for name, files in third_party_imports(REPO_ROOT / "tests").items():
        dist = canonical(IMPORT_TO_DISTRIBUTION.get(name, name))
        if dist not in declared:
            offenders[name] = files
    assert not offenders, (
        "undeclared test dependency: " + "; ".join(
            f"{n} (imported by {', '.join(sorted(p.name for p in f))})"
            for n, f in sorted(offenders.items())))


# --------------------------------------------------------------------------
# configuration lives in exactly one place
# --------------------------------------------------------------------------

def test_pytest_config_is_not_duplicated():
    """pytest.ini outranks pyproject.toml, so two configs means one is a lie.

    The config was moved into `[tool.pytest.ini_options]` and pytest.ini
    deleted. If someone reinstates pytest.ini, the pyproject block silently
    stops being read -- this fails instead.
    """
    assert not (REPO_ROOT / "pytest.ini").exists(), (
        "pytest.ini exists again; it overrides [tool.pytest.ini_options] in "
        "pyproject.toml. Keep the configuration in one file.")
    assert not (REPO_ROOT / "setup.cfg").exists()
    assert not (REPO_ROOT / "tox.ini").exists()

    options = load_pyproject()["tool"]["pytest"]["ini_options"]
    assert options["asyncio_mode"] == "auto"
    assert options["testpaths"] == ["tests"]


def test_package_discovery_excludes_tests_and_audit():
    find = load_pyproject()["tool"]["setuptools"]["packages"]["find"]
    assert "reconkg*" in find["include"]
    assert "tests*" in find["exclude"]
    assert "audit*" in find["exclude"]
