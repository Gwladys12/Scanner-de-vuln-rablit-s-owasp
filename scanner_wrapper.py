import subprocess
import json
import os
import uuid
import datetime
from scanner.zap_api import run_zap_scan  # ✅ intégration ZAP

def run_scan(config):
    """
    Exécute ton script d'analyse OWASP + (optionnellement) OWASP ZAP via son API.
    config = {
        'target': 'https://example.com',
        'max_pages': 5,
        'selenium': False,
        'active_csrf': False,
        'broken_auth': False,
        'idor': False,
        'use_zap': True/False,
        'zap_apikey': 'clé_API',
        'zap_host': '127.0.0.1',
        'zap_port': 8090,
        'use_active_zap': False
    }
    """

    # 🔹 1. Générer un ID unique pour chaque analyse
    run_id = f"{datetime.datetime.now():%Y%m%d_%H%M%S}_{uuid.uuid4().hex[:6]}"
    result_dir = os.path.join("results", run_id)
    os.makedirs(result_dir, exist_ok=True)
    output_path = os.path.join(result_dir, "report.json")

    # 🔹 2. Chemin absolu vers ton script d’analyse local
    script_path = (
        r"C:\Users\HP-PC\ZAP\Outil-daudit-de-s-curit-Web-bas-sur-lOWASP-Top-10-main\my_zap_script.py"
    )

    # 🔹 3. Construire la commande
    cmd = [
        "python",
        script_path,
        config["target"],  # argument positionnel (pas --target)
        "--max-pages", str(config.get("max_pages", 5)),
        "--output", output_path,
        
    ]

    # 🔹 4. Ajouter les options activées
    if config.get("selenium"):
        cmd.append("--selenium")
    if config.get("active_csrf"):
        cmd.append("--active-csrf")
    if config.get("broken_auth"):
        cmd.append("--broken-auth")
    if config.get("idor"):
        cmd.append("--idor")

    # 🔹 5. Fichier de logs
    log_file = os.path.join(result_dir, f"scan_{run_id}.log")

    # 🔹 6. Exécuter le script et enregistrer les logs
    with open(log_file, "w") as lf:
        try:
            subprocess.run(cmd, check=True, stdout=lf, stderr=lf)
        except subprocess.CalledProcessError as e:
            lf.write(f"\n[ERREUR] Échec du script principal : {e}\n")

    # 🔹 7. Lire le rapport JSON s’il existe
    data = {}
    if os.path.exists(output_path):
        with open(output_path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {"message": "Rapport généré, mais non JSON lisible."}
    else:
        data = {"message": "Aucun rapport généré par le script principal."}

    # 🔹 8. Résultat de base
    result = {
        "run_id": run_id,
        "output_path": output_path,
        "log_file": log_file,
        "summary": data,
    }

    # 🔹 9. (Optionnel) Intégration OWASP ZAP si activée
    if config.get("use_zap"):
        zap_cfg = {
            "target": config["target"],
            "run_id": f"{run_id}_zap",
            "result_dir": result_dir,
            "zap_apikey": config.get("zap_apikey", "abghh357o0ltuuf1gjrcompj1m"),
            "zap_host": config.get("zap_host", "127.0.0.1"),
            "zap_port": int(config.get("zap_port", 8080)),
            "use_spider": True,
            "use_active": bool(config.get("use_active_zap", False)),
        }

        try:
            zap_res = run_zap_scan(zap_cfg)
            result["zap_result"] = zap_res
        except Exception as e:
            result["zap_error"] = f"Erreur lors du scan OWASP ZAP : {e}"

    # 🔹 10. Retour final
    return result
