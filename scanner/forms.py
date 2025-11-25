#Ce formulaire permet à l’utilisateur de choisir ses options d’analyse.
from django import forms

class ScanForm(forms.Form):
    # ------- Script local -------
    target = forms.URLField(
        label="URL à analyser",
        help_text="Entrez une URL valide (ex: https://example.com)"
    )

    max_pages = forms.IntegerField(
        label="Nombre max de pages",
        initial=5,
        required=False
    )

    selenium = forms.BooleanField(
        label="Activer Selenium (JS rendering)",
        required=False
    )

    active_csrf = forms.BooleanField(
        label="Tester CSRF actif",
        required=False
    )

    broken_auth = forms.BooleanField(
        label="Tester Broken Auth",
        required=False
    )

    idor = forms.BooleanField(
        label="Tester IDOR",
        required=False
    )

    confirm_legal = forms.BooleanField(
        label="Je confirme avoir l’autorisation d’analyser cette cible",
        required=True
    )

    # ------- OPTIONS ZAP -------
    use_zap = forms.BooleanField(
        required=False,
        initial=True,
        label="Activer l’analyse OWASP ZAP"
    )

    zap_apikey = forms.CharField(
        required=False,
        initial="abghh357o0ltuuf1gjrcompj1m",
        label="Clé API ZAP"
    )

    zap_host = forms.CharField(
        required=False,
        initial="127.0.0.1",
        label="ZAP Host"
    )

    zap_port = forms.IntegerField(
        required=False,
        initial=8080,   # ⚠️ pas 8090 dans ton cas
        label="ZAP Port"
    )

    use_active_zap = forms.BooleanField(
        required=False,
        label="Activer l’active scan ZAP (intrusif)"
    )
