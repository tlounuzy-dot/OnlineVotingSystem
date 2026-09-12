from datetime import timedelta
from django.contrib.auth import get_user_model
from django.test import TestCase, override_settings
from django.urls import reverse
from django.utils import timezone
from cryptography.fernet import Fernet
from accounts.models import AuditLog, Role, Voter
from elections.models import Candidate, Election
from .models import Vote
from .services import decrypt_choice

@override_settings(VOTE_ENCRYPTION_KEY=Fernet.generate_key().decode())
class VotingFlowTests(TestCase):
    def setUp(self):
        role=Role.objects.create(name="Voter"); admin_role=Role.objects.create(name="Admin")
        self.admin=get_user_model().objects.create_user(email="admin@vote.test",password="ValidPass!42",full_name="Admin",role=admin_role,status="active",is_staff=True)
        self.user=get_user_model().objects.create_user(email="voter@vote.test",password="ValidPass!42",full_name="Voter",role=role,status="active")
        self.voter=Voter.objects.create(user=self.user,id_number="VOTE-1",date_of_birth="2000-01-01",status="verified")
        self.election=Election.objects.create(title="Open",start_date=timezone.now()-timedelta(hours=1),end_date=timezone.now()+timedelta(hours=1),status="active",created_by=self.admin)
        self.candidate=Candidate.objects.create(election=self.election,full_name="Choice",party="Party")
    def verified(self):
        self.client.force_login(self.user);s=self.client.session;s["webauthn_verified_voter_id"]=self.voter.pk;s.save()
    def test_verified_voter_submits_encrypted_single_vote_and_audit(self):
        self.verified();self.client.post(reverse("voting:choose",args=[self.election.pk]),{"candidate":self.candidate.pk});self.assertEqual(self.client.post(reverse("voting:submit",args=[self.election.pk])).status_code,302)
        vote=Vote.objects.get();self.assertNotEqual(vote.encrypted_choice,str(self.candidate.pk).encode());self.assertEqual(decrypt_choice(vote.encrypted_choice),self.candidate.pk);self.assertTrue(AuditLog.objects.filter(action="vote_submitted").exists());self.client.post(reverse("voting:submit",args=[self.election.pk]));self.assertEqual(Vote.objects.count(),1)
    def test_unverified_inactive_candidate_and_closed_election_cannot_vote(self):
        self.client.force_login(self.user);self.assertEqual(self.client.get(reverse("voting:ballot",args=[self.election.pk])).status_code,403)
        self.verified();self.candidate.status="inactive";self.candidate.save();self.assertEqual(self.client.post(reverse("voting:choose",args=[self.election.pk]),{"candidate":self.candidate.pk}).status_code,404);self.election.status="closed";self.election.save();self.assertEqual(self.client.get(reverse("voting:ballot",args=[self.election.pk])).status_code,302)
