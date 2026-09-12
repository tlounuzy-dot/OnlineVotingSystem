from django.urls import path
from . import views
app_name = "elections"
urlpatterns = [
    path("admin/dashboard/", views.dashboard, name="dashboard"), path("admin/elections/", views.election_list, name="list"), path("admin/elections/create/", views.election_create, name="create"), path("admin/elections/<int:pk>/", views.election_detail, name="detail"), path("admin/elections/<int:pk>/edit/", views.election_edit, name="edit"), path("admin/elections/<int:pk>/<str:status>/", views.election_transition, name="transition"),
    path("admin/candidates/", views.candidate_list, name="candidate_list"), path("admin/candidates/create/", views.candidate_create, name="candidate_create"), path("admin/candidates/<int:pk>/edit/", views.candidate_edit, name="candidate_edit"), path("admin/candidates/<int:pk>/deactivate/", views.candidate_deactivate, name="candidate_deactivate"), path("dashboard/", views.voter_dashboard, name="voter_dashboard")]
