from django.urls import path
from . import views
app_name = "voting"
urlpatterns = [path("elections/<int:election_pk>/vote/", views.ballot, name="ballot"), path("elections/<int:election_pk>/choose/", views.choose_candidate, name="choose"), path("elections/<int:election_pk>/confirm/", views.confirm_vote, name="confirm"), path("elections/<int:election_pk>/submit/", views.submit_vote, name="submit"), path("elections/<int:election_pk>/receipt/", views.receipt, name="receipt")]
