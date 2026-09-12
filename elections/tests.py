from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from accounts.models import Role, Voter
from .models import Candidate, Election

class ElectionAccessTests(TestCase):
    def setUp(self):
        admin_role=Role.objects.create(name="Admin"); voter_role=Role.objects.create(name="Voter")
        self.admin=get_user_model().objects.create_user(email="admin@test.com",password="ValidPass!42",full_name="Admin",role=admin_role,status="active",is_staff=True)
        self.user=get_user_model().objects.create_user(email="voter@test.com",password="ValidPass!42",full_name="Voter",role=voter_role,status="active")
        self.voter=Voter.objects.create(user=self.user,id_number="V-1",date_of_birth="2000-01-01",status="verified")
        self.election=Election.objects.create(title="Election",start_date=timezone.now()+timedelta(days=1),end_date=timezone.now()+timedelta(days=2),created_by=self.admin)
    def test_admin_creates_and_edits_election_and_candidate(self):
        self.client.force_login(self.admin); r=self.client.post(reverse("elections:create"),{"title":"New","description":"","start_date":"2030-01-01T10:00","end_date":"2030-01-01T11:00","status":"pending"}); self.assertEqual(r.status_code,302); e=Election.objects.get(title="New")
        self.assertEqual(self.client.post(reverse("elections:edit",args=[e.pk]),{"title":"Changed","description":"","start_date":"2030-01-01T10:00","end_date":"2030-01-01T12:00","status":"pending"}).status_code,302)
        self.assertEqual(self.client.post(reverse("elections:candidate_create"),{"election":self.election.pk,"full_name":"Candidate","party":"Party","manifesto":"","status":"approved"}).status_code,302)
    def test_invalid_dates_rejected_and_status_calculated(self):
        self.client.force_login(self.admin); r=self.client.post(reverse("elections:create"),{"title":"Bad","start_date":"2030-01-02T10:00","end_date":"2030-01-01T10:00","status":"pending"}); self.assertEqual(r.status_code,200); self.assertFalse(Election.objects.filter(title="Bad").exists()); self.assertEqual(self.election.calculated_status,Election.Status.PENDING)
    def test_voter_and_anonymous_cannot_manage_admin_routes(self):
        urls=[reverse("elections:dashboard"),reverse("elections:list"),reverse("elections:candidate_list")]
        for url in urls:self.assertEqual(self.client.get(url).status_code,302)
        self.client.force_login(self.user)
        for url in urls:self.assertEqual(self.client.get(url).status_code,403)
