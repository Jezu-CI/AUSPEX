"""Analyse de code (linter) : ruff, règles de pyproject.toml ([tool.ruff]).

Erreurs probables et pièges courants (noms indéfinis, imports inutiles, exceptions
qui masquent leur cause, fermetures sur une variable de boucle…). Exécuté dans la CI
dès que ruff est installé (requirements/dev.txt).
"""
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def test_ruff_clean():
    ruff = shutil.which("ruff")
    if not ruff:
        pytest.skip("ruff absent (pip install --require-hashes -r requirements/dev.txt)")
    r = subprocess.run([ruff, "check", "--output-format", "concise", "."], cwd=ROOT,
                       capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
