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


class ElectionDetailPublicationUXTests(TestCase):
    def setUp(self):
        admin_role = Role.objects.create(name="Admin")
        self.admin = get_user_model().objects.create_user(
            email="detail-admin@example.test", password="ValidPass!42", full_name="Detail Admin",
            role=admin_role, status="active", is_staff=True,
        )
        now = timezone.now()
        self.closed = Election.objects.create(
            title="Manually closed", start_date=now - timedelta(hours=1),
            end_date=now + timedelta(hours=1), status=Election.Status.CLOSED,
            created_by=self.admin,
        )
        self.open = Election.objects.create(
            title="Open", start_date=now - timedelta(hours=1), end_date=now + timedelta(hours=1),
            status=Election.Status.ACTIVE, created_by=self.admin,
        )
        self.pending = Election.objects.create(
            title="Pending", start_date=now + timedelta(days=1), end_date=now + timedelta(days=2),
            status=Election.Status.PENDING, created_by=self.admin,
        )
        self.client.force_login(self.admin)

    def _detail(self, election):
        return self.client.get(reverse("elections:detail", args=[election.pk]))

    def test_closed_unpublished_election_shows_csrf_protected_publish_action_only(self):
        response = self._detail(self.closed)

        self.assertEqual(self.closed.calculated_status, Election.Status.CLOSED)
        self.assertContains(response, "Publish final results")
        self.assertContains(response, reverse("elections:publish_results", args=[self.closed.pk]))
        self.assertContains(response, "csrfmiddlewaretoken")
        self.assertNotContains(response, ">Activate<")
        self.assertNotContains(response, ">Close<")

    def test_open_and_pending_elections_do_not_offer_result_publication(self):
        self.assertNotContains(self._detail(self.open), "Publish final results")
        self.assertNotContains(self._detail(self.pending), "Publish final results")

    def test_published_election_shows_timestamp_and_no_repeat_publish_action(self):
        self.closed.results_published_at = timezone.now()
        self.closed.save(update_fields=["results_published_at"])

        response = self._detail(self.closed)

        self.assertContains(response, "Published")
        self.assertNotContains(response, "Publish final results")
