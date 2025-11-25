# Outil-daudit-de-s-curit-Web-bas-sur-lOWASP-Top-10

## Projet 

## Ce que fait le script

* Crawl du site (limité au domaine) jusqu’à ``--max-pages``.

* Pour chaque page : collecte headers, cookies, missing security headers.

* Extraction des formulair es HTML (et, si ``--selenium`` activé, aussi des formulaires ajoutés par JS via rendu).

* Passive checks (sans envoyer données nuisibles) :

- présence/absence de token CSRF sur formulaires (champ ``hidden`` avec noms courants) ;

- détection de formulaires de login et mauvaises pratiques (méthode ``GET``, absence CSRF) ;

- rapports d’en-têtes de sécurité manquants.

* Tests actifs non destructifs :

- injection de payloads SQLi basiques dans champs textuels et analyse des erreurs SQL / variation de taille de réponse ;

- injection de payloads XSS (avec marqueur ``__XSS_TEST__``), puis (si ``--selenium``) rendu de la page résultante et vérification de la présence du marqueur dans le DOM rendu.

* Sauvegarde complète des conclusions et preuves (par page / par formulaire / par test) dans un fichier JSON.

* Tests OWASP supplémentaires (options activables) :

- CSRF enforcement test actif (--active-csrf) : on soumet un formulaire en retirant le token CSRF (si présent) pour vérifier s’il est exigé ;

- Broken Authentication tests avancés (--broken-auth) : tests passifs (ex. formulaire de login utilisant GET, absence token CSRF, champ password sans contraintes) + tests actifs optionnels (tentative de login avec couple d’identifiants faibles si tu fournis --weak-creds file.txt) ;

- IDOR tests basiques (--idor) : repère les URLs avec segments numériques et tente d’incrémenter/décrémenter l’ID pour voir si on accède à d’autres ressources (heuristique non destructive).

* Authentification :

- HTTP Basic Auth via --http-auth username:password (appliqué à la session requests),

- Form-based login optionnel via --login username:password : le script va essayer d’identifier un formulaire de login et l’utiliser pour s’authentifier avant le crawl.

* Génération d’un rapport HTML lisible (--html-report report.html) résumant les vulnérabilités potentielles triées par criticité (High / Medium / Low), plus export JSON (par défaut).

* Toutes les options CLI habituelles (--output, --delay, --max-pages, --selenium, etc.).

* Plusieurs protections éthiques : tests actifs dangereux sont désactivés par défaut et ne s’exécutent que si tu passes explicitement les flags --active-csrf, --broken-auth ou --idor. Avertissement fortement affiché.

## Installer les dépendances

* Installer d'abord ``python3*``

* `` pip install requests beautifulsoup4 selenium webdriver-manager jinja2 ``

* ``selenium`` + ``webdriver-manager`` pour le rendu JS (``--selenium``).

* ``jinja2`` pour la génération HTML.


## Mode d’emploi rapide

1. Exécution simple (passive + tests de base) :

``python full_owasp_tester.py https://example.com --max-pages 5 --output report.json``

2. Avec HTML généré et rendu JS (Selenium) :

``python full_owasp_tester.py https://example.com --max-pages 5 --selenium --html-report report.html``

3. Activer tests actifs (CSRF enforcement, IDOR, Broken Auth using weak creds) — active tests = use with explicit consent :

``python full_owasp_tester.py https://staging.example.com --max-pages 10 --active-csrf --idor --broken-auth --weak-creds weak.txt --output report.json --html-report report.html``

4. Si ton site nécessite HTTP Basic Auth :

``python full_owasp_tester.py https://example.com --http-auth user:password``

5. Si tu veux tenter une connexion via formulaire avant le crawl (form-based login) :

``python full_owasp_tester.py https://staging.example.com --login testuser:password``

