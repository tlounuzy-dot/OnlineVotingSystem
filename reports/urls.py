from django.urls import path
from . import views
app_name = "reports"
urlpatterns = [path("results/", views.voter_results, name="voter_results"), path("admin/results/", views.admin_results, name="admin_results"), path("admin/reports/", views.report_list, name="report_list"), path("admin/reports/export/", views.export_csv, name="export_csv"), path("admin/audit-logs/", views.audit_logs, name="audit_logs")]
