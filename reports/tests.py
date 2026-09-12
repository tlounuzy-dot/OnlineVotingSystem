from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from accounts.models import Role, Voter
from elections.models import Candidate, Election
from .models import Result

class ReportAccessTests(TestCase):
 def setUp(self):
  ar=Role.objects.create(name="Admin");vr=Role.objects.create(name="Voter");self.admin=get_user_model().objects.create_user(email="a@r.test",password="ValidPass!42",full_name="Admin",role=ar,status="active",is_staff=True);self.user=get_user_model().objects.create_user(email="v@r.test",password="ValidPass!42",full_name="Voter",role=vr,status="active");self.voter=Voter.objects.create(user=self.user,id_number="R-1",date_of_birth="2000-01-01",status="verified");self.e=Election.objects.create(title="Results",start_date=timezone.now()-timedelta(days=2),end_date=timezone.now()-timedelta(days=1),status="closed",created_by=self.admin);self.c=Candidate.objects.create(election=self.e,full_name="Zero",party="P");Result.objects.create(election=self.e,candidate=self.c,total_votes=0,percentage=0)
 def test_admin_results_reports_csv_and_chart_use_real_zero_data(self):
  self.client.force_login(self.admin);r=self.client.get(reverse("reports:admin_results"));self.assertContains(r,"chart.js");self.assertContains(r,"Zero");self.assertContains(r,"0");self.assertEqual(self.client.get(reverse("reports:report_list")).status_code,200);csv=self.client.get(reverse("reports:export_csv"));self.assertContains(csv,"Results");self.assertNotContains(csv,"encrypted_choice")
 def test_voter_cannot_access_admin_reports_results_or_audit(self):
  self.client.force_login(self.user)
  for url in [reverse("reports:admin_results"),reverse("reports:report_list"),reverse("reports:export_csv"),reverse("reports:audit_logs")]:self.assertEqual(self.client.get(url).status_code,403)
