from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from accounts.models import AuditLog, Role, Voter
from elections.models import Candidate, Election
from cryptography.fernet import Fernet
from voting.models import Vote
from .models import Result

class ReportAccessTests(TestCase):
 def setUp(self):
  ar=Role.objects.create(name="Admin");vr=Role.objects.create(name="Voter");self.admin=get_user_model().objects.create_user(email="a@r.test",password="ValidPass!42",full_name="Admin",role=ar,status="active",is_staff=True);self.user=get_user_model().objects.create_user(email="v@r.test",password="ValidPass!42",full_name="Voter",role=vr,status="active");self.voter=Voter.objects.create(user=self.user,id_number="R-1",date_of_birth="2000-01-01",status="verified");self.e=Election.objects.create(title="Results",start_date=timezone.now()-timedelta(days=2),end_date=timezone.now()-timedelta(days=1),status="closed",created_by=self.admin);self.c=Candidate.objects.create(election=self.e,full_name="Zero",party="P");Result.objects.create(election=self.e,candidate=self.c,total_votes=0,percentage=0)
 def test_admin_results_reports_csv_and_chart_use_real_zero_data(self):
  self.client.force_login(self.admin);r=self.client.get(reverse("reports:admin_results"));self.assertContains(r,"chart.js");self.assertContains(r,"Zero");self.assertContains(r,"0");self.assertEqual(self.client.get(reverse("reports:report_list")).status_code,200);csv=self.client.get(reverse("reports:export_csv"));self.assertContains(csv,"Results");self.assertNotContains(csv,"encrypted_choice")
 def test_voter_cannot_access_admin_reports_results_or_audit(self):
  self.client.force_login(self.user)
  for url in [reverse("reports:admin_results"),reverse("reports:report_list"),reverse("reports:export_csv"),reverse("reports:audit_logs")]:self.assertEqual(self.client.get(url).status_code,403)


@override_settings(VOTE_ENCRYPTION_KEY=Fernet.generate_key().decode())
class ResultPublicationTests(TestCase):
 def setUp(self):
  ar=Role.objects.create(name="Admin");vr=Role.objects.create(name="Voter")
  self.admin=get_user_model().objects.create_user(email="publish-admin@example.test",password="ValidPass!42",full_name="Admin",role=ar,status="active",is_staff=True)
  self.user=get_user_model().objects.create_user(email="publish-voter@example.test",password="ValidPass!42",full_name="Voter",role=vr,status="active")
  self.voter=Voter.objects.create(user=self.user,id_number="PUBLISH-1",date_of_birth="2000-01-01",status="verified")
  self.closed=Election.objects.create(title="Closed result",start_date=timezone.now()-timedelta(days=2),end_date=timezone.now()-timedelta(days=1),status="closed",created_by=self.admin)
  self.candidate=Candidate.objects.create(election=self.closed,full_name="Final Candidate",party="P")
  Result.objects.create(election=self.closed,candidate=self.candidate,total_votes=0,percentage=0)
  self.open=Election.objects.create(title="Open result",start_date=timezone.now()-timedelta(hours=1),end_date=timezone.now()+timedelta(hours=1),status="active",created_by=self.admin)

 def _verified_voter(self):
  self.client.force_login(self.user);session=self.client.session;session["webauthn_verified_voter_id"]=self.voter.pk;session.save()

 def test_unpublished_closed_results_are_hidden_from_voters(self):
  self._verified_voter()
  response=self.client.get(reverse("reports:voter_results"))
  self.assertContains(response,"No results have been published.")
  self.assertNotContains(response,"Final Candidate")

 def test_admin_can_publish_closed_results_once_and_voters_then_see_them(self):
  self.client.force_login(self.admin)
  publish_url=reverse("elections:publish_results",args=[self.closed.pk])
  response=self.client.post(publish_url)
  self.assertRedirects(response,reverse("elections:detail",args=[self.closed.pk]))
  self.closed.refresh_from_db()
  self.assertIsNotNone(self.closed.results_published_at)
  self.assertTrue(AuditLog.objects.filter(user=self.admin,action="election_results_published").exists())
  response=self.client.post(publish_url,follow=True)
  self.assertContains(response,"already been published")
  self._verified_voter()
  response=self.client.get(reverse("reports:voter_results"))
  self.assertContains(response,"Final Candidate")
  self.assertContains(response,"Published")

 def test_admin_cannot_publish_open_results_and_voter_cannot_publish(self):
  self.client.force_login(self.admin)
  response=self.client.post(reverse("elections:publish_results",args=[self.open.pk]),follow=True)
  self.assertContains(response,"only after the election has closed")
  self.open.refresh_from_db();self.assertIsNone(self.open.results_published_at)
  self._verified_voter()
  self.assertEqual(self.client.post(reverse("elections:publish_results",args=[self.closed.pk])).status_code,403)

 def test_manually_closed_published_election_shows_real_final_results_after_refresh(self):
  lifecycle = Election.objects.create(
   title="Lifecycle result", start_date=timezone.now()-timedelta(hours=1),
   end_date=timezone.now()+timedelta(hours=1), status=Election.Status.ACTIVE,
   created_by=self.admin,
  )
  candidate = Candidate.objects.create(election=lifecycle, full_name="Lifecycle Candidate", party="P")

  self._verified_voter()
  self.assertEqual(self.client.post(reverse("voting:choose", args=[lifecycle.pk]), {"candidate": candidate.pk}).status_code, 302)
  self.assertEqual(self.client.post(reverse("voting:submit", args=[lifecycle.pk])).status_code, 302)
  self.assertEqual(Vote.objects.filter(election=lifecycle).count(), 1)
  self.assertContains(self.client.get(reverse("reports:voter_results")), "No results have been published.")

  self.client.force_login(self.admin)
  self.assertEqual(self.client.post(reverse("elections:transition", args=[lifecycle.pk, "closed"])).status_code, 302)
  lifecycle.refresh_from_db()
  self.assertEqual(lifecycle.calculated_status, Election.Status.CLOSED)
  self.assertIsNone(lifecycle.results_published_at)

  self.assertEqual(self.client.post(reverse("elections:publish_results", args=[lifecycle.pk])).status_code, 302)
  lifecycle.refresh_from_db()
  self.assertIsNotNone(lifecycle.results_published_at)
  result = Result.objects.get(election=lifecycle, candidate=candidate)
  self.assertEqual(result.total_votes, 1)

  self._verified_voter()
  results_url = reverse("reports:voter_results")
  self.assertContains(self.client.get(results_url), "Lifecycle Candidate")
  self.assertContains(self.client.get(results_url), "Lifecycle Candidate")
