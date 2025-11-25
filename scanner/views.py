from django.shortcuts import render
from django.http import JsonResponse, FileResponse, Http404
from .forms import ScanForm
from scanner_wrapper import run_scan
from scanner.utils.report_generator import generate_report
import os, json

def home(request):
    """Affiche le formulaire et lance le scan OWASP + ZAP"""
    if request.method == "POST":
        form = ScanForm(request.POST)

        if form.is_valid():
            config = form.cleaned_data.copy()

            # ⚠️ Garantir le bon format du port ZAP
            try:
                config["zap_port"] = int(config.get("zap_port", 8080))
            except:
                config["zap_port"] = 8080

            # ⚠️ Éviter les None
            config["zap_host"] = config.get("zap_host") or "127.0.0.1"
            config["zap_apikey"] = config.get("zap_apikey") or ""

            # ⚠️ Par sécurité : si use_zap = False, on n'active pas ZAP
            if not config.get("use_zap", False):
                config["use_active_zap"] = False

            # Lancer ton wrapper (script local + ZAP si activé)
            result = run_scan(config)

            return render(request, "scanner/result.html", {"result": result})

    else:
        form = ScanForm()

    return render(request, "scanner/home.html", {"form": form})


def get_result(request, run_id):
    """Retourne le rapport JSON généré par ton script local"""
    path = os.path.join("results", run_id, "report.json")

    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {"message": "Le rapport existe mais n'est pas du JSON valide."}

        return JsonResponse(data)

    return JsonResponse({"error": "Rapport introuvable"}, status=404)


def export_report(request, run_id, format):
    """Génère un export PDF/HTML/Docx si tu l'utilises"""
    try:
        report_path = generate_report(run_id, format)
        return FileResponse(open(report_path, "rb"), as_attachment=True)
    except Exception as e:
        raise Http404(f"Erreur lors de la génération du rapport : {e}")


from django.http import FileResponse, Http404
import os

def serve_result_file(request, path):
    """
    Sert les fichiers générés dans le dossier /results/<run_id>/ (rapports ZAP).
    Exemple : /results/<run_id>/<run_id>_zap.html
    """
    full_path = os.path.join("results", path)

    if not os.path.exists(full_path):
        raise Http404("Fichier introuvable")

    return FileResponse(open(full_path, "rb"))
