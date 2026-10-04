#!/usr/bin/env python3
"""User-operated deployment only. Never pass a token in arguments or a file.

The token is read from a real terminal without echo and given only to the child
process environment. No token is returned to an assistant, printed or persisted
by this wrapper. Child output is discarded, including error/debug output.
"""
import argparse
import getpass
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import warnings

ROOT = Path(__file__).resolve().parent.parent
CONFIG = ROOT / "wrangler.probe.jsonc"
EXPECTED_CONFIG = {
    "$schema": "node_modules/wrangler/config-schema.json",
    "name": "icloud-mcp",
    "main": "scripts/cloud-probe/worker.ts",
    "compatibility_date": "2026-08-01",
    "compatibility_flags": ["nodejs_compat"],
    "workers_dev": True,
    "preview_urls": False,
    "durable_objects": {"bindings": [{"name": "PROBE", "class_name": "CloudProbe"}]},
    "exports": {"CloudProbe": {"type": "durable-object", "storage": "sqlite"}},
    "observability": {"enabled": False},
    "logpush": False,
}


def checked_config():
    if json.loads(CONFIG.read_text()) != EXPECTED_CONFIG:
        raise ValueError("La configuration de sonde a changé ; arrêt avant saisie du jeton.")
    package = json.loads((ROOT / "node_modules/wrangler/package.json").read_text())
    if package["version"] != "4.122.0":
        raise ValueError("Version de Wrangler inattendue ; arrêt avant saisie du jeton.")


def child_environment(account, token, inherited):
    # Deliberately do not inherit NODE_OPTIONS, API endpoint overrides, proxy
    # settings, other credentials, telemetry or debug options from the shell.
    env = {key: inherited[key] for key in ("PATH", "HOME", "TMPDIR", "LANG", "LC_ALL") if key in inherited}
    env.update({
        "CLOUDFLARE_ACCOUNT_ID": account,
        "CLOUDFLARE_API_TOKEN": token,
        "WRANGLER_WRITE_LOGS": "false",
        "WRANGLER_LOG_SANITIZE": "true",
        "WRANGLER_LOG": "error",
        "WRANGLER_SEND_METRICS": "false",
        "WRANGLER_SEND_ERROR_REPORTS": "false",
        "DO_NOT_TRACK": "1",
        "CI": "true",
    })
    return env


def hidden_token():
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("Ouvrez ce lanceur dans votre terminal, sans redirection ni enregistrement.")
    # getpass normally falls back to echoed input if terminal control fails.
    # Turn that warning into a failure before it can read an unmasked secret.
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", getpass.GetPassWarning)
            token = getpass.getpass("Jeton temporaire (saisie masquée, puis Entrée) : ")
    except getpass.GetPassWarning:
        raise ValueError("La saisie masquée est indisponible ; aucun jeton demandé.") from None
    if not re.fullmatch(r"[A-Za-z0-9_-]{20,256}", token):
        raise ValueError("Format du jeton refusé. Aucune valeur affichée ou conservée.")
    return token


def deploy(account, token, node, runner=subprocess.run):
    env = child_environment(account, token, os.environ)
    try:
        result = runner(
            [node, str(ROOT / "node_modules/wrangler/bin/wrangler.js"),
             "deploy", "--config", str(CONFIG), "--env-file", os.devnull],
            cwd=ROOT, env=env, stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
            timeout=180, check=False,
        )
        return result.returncode
    finally:
        env.pop("CLOUDFLARE_API_TOKEN", None)


def main():
    parser = argparse.ArgumentParser(description="Déployer uniquement la sonde icloud-mcp avec un jeton éphémère masqué.")
    parser.add_argument("--account", required=True, help="ID du compte Cloudflare spécifique approuvé (pas un secret)")
    args = parser.parse_args()
    token = None
    try:
        if not re.fullmatch(r"[0-9a-f]{32}", args.account):
            raise ValueError("ID de compte invalide.")
        checked_config()
        node = shutil.which("node")
        if not node:
            raise ValueError("Node.js est introuvable dans ce terminal.")
        print("Sonde uniquement : icloud-mcp + un Durable Object SQLite.")
        print("Compte cible : " + args.account)
        print("Aucun accès iCloud. Aucun abonnement. Aucun jeton dans le chat ou un fichier.")
        token = hidden_token()
        print("Déploiement en cours. La sortie de Wrangler est volontairement masquée.", flush=True)
        code = deploy(args.account, token, node)
        token = None
        if code == 0:
            print("DEPLOIEMENT_REUSSI. Fermez la page affichant le jeton, puis informez Codex.")
            print("Révoquez le jeton après le test ; le jeton n'est pas nécessaire pour exécuter la sonde publique.")
            return 0
        print("DEPLOIEMENT_NON_CONFIRME (code %s). Ne collez aucun jeton ou journal ; signalez uniquement ce code." % code)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\nSaisie ou déploiement interrompu. Vérifier le Worker avant toute nouvelle tentative.")
        return 130
    except ValueError as error:
        # Only messages authored above; never include input, env or subprocess output.
        print(str(error))
        return 1
    except Exception:
        print("DEPLOIEMENT_NON_CONFIRME. Vérifier le Worker avant toute nouvelle tentative. Aucun détail sensible affiché.")
        return 1
    finally:
        token = None


if __name__ == "__main__":
    sys.exit(main())
