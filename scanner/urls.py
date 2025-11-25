from django.urls import path, re_path
from . import views

urlpatterns = [
    path("", views.home, name="home"),  # page d'accueil avec le formulaire
    path("result/<str:run_id>/", views.get_result, name="get_result"),  # accès JSON au rapport
    path("export/<str:run_id>/<str:format>/", views.export_report, name="export_report"),
     # ⚠️ Sert tous les fichiers statiques dans /results/
    re_path(r"^results/(?P<path>.*)$", views.serve_result_file, name="serve_result_file"),
]
