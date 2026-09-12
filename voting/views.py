from decimal import Decimal

from django.contrib import messages
from django.db import IntegrityError, transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from accounts.models import AuditLog
from accounts.permissions import verified_voter_required
from elections.models import Candidate, Election
from reports.models import Result
from .models import Vote
from .services import encrypt_choice


def _ip(request):
    return request.META.get("HTTP_X_FORWARDED_FOR", "").split(",")[0].strip() or request.META.get("REMOTE_ADDR")


def _record_results(election):
    totals = {row["candidate_id"]: row["total"] for row in Vote.objects.filter(election=election, status=Vote.Status.VALID).values("candidate_id").annotate(total=Count("id"))}
    total_votes = sum(totals.values())
    for candidate in election.candidates.all():
        count = totals.get(candidate.pk, 0)
        percentage = Decimal(count) * Decimal("100") / total_votes if total_votes else Decimal("0")
        Result.objects.update_or_create(election=election, candidate=candidate, defaults={"total_votes": count, "percentage": percentage.quantize(Decimal("0.01"))})


@verified_voter_required
def ballot(request, election_pk):
    election = get_object_or_404(Election, pk=election_pk)
    if not election.is_open_for_voting or Vote.objects.filter(voter=request.voter, election=election).exists():
        messages.error(request, "This election is unavailable, or you have already voted.")
        return redirect("elections:voter_dashboard")
    return render(request, "voting/ballot.html", {"election": election, "candidates": election.candidates.filter(status=Candidate.Status.APPROVED)})


@verified_voter_required
@require_POST
def choose_candidate(request, election_pk):
    election = get_object_or_404(Election, pk=election_pk)
    if not election.is_open_for_voting:
        messages.error(request, "This election is not currently open for voting.")
        return redirect("elections:voter_dashboard")
    candidate = get_object_or_404(Candidate, pk=request.POST.get("candidate"), election=election, status=Candidate.Status.APPROVED)
    request.session["pending_vote"] = {"election": election.pk, "candidate": candidate.pk}
    return redirect("voting:confirm", election_pk=election.pk)


@verified_voter_required
def confirm_vote(request, election_pk):
    pending = request.session.get("pending_vote", {})
    if pending.get("election") != election_pk:
        messages.error(request, "Choose a candidate before confirming your vote.")
        return redirect("voting:ballot", election_pk=election_pk)
    election = get_object_or_404(Election, pk=election_pk)
    candidate = get_object_or_404(Candidate, pk=pending.get("candidate"), election=election)
    return render(request, "voting/confirm.html", {"election": election, "candidate": candidate})


@verified_voter_required
@require_POST
def submit_vote(request, election_pk):
    pending = request.session.get("pending_vote", {})
    if pending.get("election") != election_pk:
        messages.error(request, "Your vote confirmation expired. Please choose again.")
        return redirect("voting:ballot", election_pk=election_pk)
    try:
        with transaction.atomic():
            voter = request.voter.__class__.objects.select_for_update().get(pk=request.voter.pk)
            election = Election.objects.select_for_update().get(pk=election_pk)
            candidate = Candidate.objects.select_for_update().get(pk=pending["candidate"], election=election, status=Candidate.Status.APPROVED)
            if voter.status != voter.Status.VERIFIED or not election.is_open_for_voting:
                raise ValueError("Voting is no longer available.")
            if Vote.objects.filter(voter=voter, election=election).exists():
                AuditLog.objects.create(user=request.user, action="duplicate_vote_attempt", description="Duplicate vote submission was blocked.", ip_address=_ip(request))
                raise IntegrityError
            vote = Vote(voter=voter, election=election, candidate=candidate, encrypted_choice=encrypt_choice(candidate.pk), ip_address=_ip(request))
            vote.full_clean(); vote.save()
            _record_results(election)
            AuditLog.objects.create(user=request.user, action="vote_submitted", description="A vote was recorded for an election.", ip_address=_ip(request))
    except Candidate.DoesNotExist:
        messages.error(request, "That candidate is no longer available. Please choose again.")
        return redirect("voting:ballot", election_pk=election_pk)
    except ValueError as exc:
        messages.error(request, str(exc)); return redirect("elections:voter_dashboard")
    except IntegrityError:
        messages.info(request, "A vote has already been recorded for this election.")
        return redirect("elections:voter_dashboard")
    request.session.pop("pending_vote", None)
    messages.success(request, "Your vote has been recorded. It cannot be changed.")
    return redirect("voting:receipt", election_pk=election_pk)


@verified_voter_required
def receipt(request, election_pk):
    election = get_object_or_404(Election, pk=election_pk)
    if not Vote.objects.filter(voter=request.voter, election=election).exists():
        return redirect("elections:voter_dashboard")
    return render(request, "voting/receipt.html", {"election": election})
