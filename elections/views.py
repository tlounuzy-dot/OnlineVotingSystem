from django.contrib import messages
from django.db import transaction
from django.db.models import Count
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone
from django.views.decorators.http import require_POST
from accounts.models import AuditLog, Voter
from accounts.permissions import admin_required, verified_voter_required
from voting.models import Vote
from .forms import CandidateForm, ElectionForm
from .models import Candidate, Election


def audit(request, action):
    AuditLog.objects.create(user=request.user, action=action, description=action.replace("_", " ").capitalize() + ".")


@admin_required
def dashboard(request):
    elections = list(Election.objects.all())
    stats = {"total_voters": Voter.objects.count(), "active_voters": Voter.objects.filter(status=Voter.Status.VERIFIED).count(), "active_elections": sum(e.is_open_for_voting for e in elections), "upcoming_elections": sum(e.calculated_status == Election.Status.PENDING for e in elections), "completed_elections": sum(e.calculated_status == Election.Status.CLOSED for e in elections), "total_votes": Vote.objects.count()}
    return render(request, "elections/admin_dashboard.html", {"stats": stats})


@admin_required
def election_list(request):
    return render(request, "elections/election_list.html", {"elections": Election.objects.select_related("created_by").annotate(candidate_count=Count("candidates"))})


@admin_required
def election_create(request):
    form = ElectionForm(request.POST or None)
    if request.method == "POST" and form.is_valid():
        election = form.save(commit=False); election.created_by = request.user; election.full_clean(); election.save(); audit(request, "election_created")
        return redirect("elections:detail", pk=election.pk)
    return render(request, "elections/form.html", {"form": form, "title": "Create election"})


@admin_required
def election_edit(request, pk):
    election = get_object_or_404(Election, pk=pk); form = ElectionForm(request.POST or None, instance=election)
    if request.method == "POST" and form.is_valid():
        form.save(); audit(request, "election_updated"); return redirect("elections:detail", pk=pk)
    return render(request, "elections/form.html", {"form": form, "title": "Edit election"})


@admin_required
def election_detail(request, pk):
    return render(request, "elections/detail.html", {"election": get_object_or_404(Election.objects.prefetch_related("candidates"), pk=pk)})


@admin_required
@require_POST
def election_transition(request, pk, status):
    election = get_object_or_404(Election, pk=pk)
    allowed = {"active": {Election.Status.PENDING}, "closed": {Election.Status.PENDING, Election.Status.ACTIVE}, "cancelled": {Election.Status.PENDING, Election.Status.ACTIVE}}
    if status in allowed and election.status in allowed[status] and not (status == "active" and not election.start_date <= timezone.now() < election.end_date):
        election.status = status; election.save(update_fields=["status"]); audit(request, "election_status_changed")
    else: messages.error(request, "That election status transition is not allowed.")
    return redirect("elections:detail", pk=pk)


@admin_required
@require_POST
def election_publish_results(request, pk):
    with transaction.atomic():
        election = get_object_or_404(Election.objects.select_for_update(), pk=pk)
        if election.calculated_status != Election.Status.CLOSED:
            messages.error(request, "Results can be published only after the election has closed.")
        elif election.results_are_published:
            messages.info(request, "These results have already been published.")
        else:
            # Recalculate immediately before publication so the stored snapshot
            # represents the final set of valid recorded votes.
            from voting.views import _record_results
            _record_results(election)
            election.results_published_at = timezone.now()
            election.save(update_fields=["results_published_at"])
            audit(request, "election_results_published")
            messages.success(request, "Final results have been published to voters.")
    return redirect("elections:detail", pk=pk)


@admin_required
def candidate_list(request): return render(request, "elections/candidate_list.html", {"candidates": Candidate.objects.select_related("election")})
@admin_required
def candidate_create(request):
    form = CandidateForm(request.POST or None)
    if request.method == "POST" and form.is_valid(): form.save(); audit(request, "candidate_created"); return redirect("elections:candidate_list")
    return render(request, "elections/form.html", {"form": form, "title": "Add candidate"})
@admin_required
def candidate_edit(request, pk):
    form = CandidateForm(request.POST or None, instance=get_object_or_404(Candidate, pk=pk))
    if request.method == "POST" and form.is_valid(): form.save(); audit(request, "candidate_updated"); return redirect("elections:candidate_list")
    return render(request, "elections/form.html", {"form": form, "title": "Edit candidate"})
@admin_required
@require_POST
def candidate_deactivate(request, pk):
    candidate = get_object_or_404(Candidate, pk=pk); candidate.status = Candidate.Status.INACTIVE; candidate.save(update_fields=["status"]); audit(request, "candidate_deactivated"); return redirect("elections:candidate_list")


@verified_voter_required
def voter_dashboard(request):
    elections = list(Election.objects.all())
    voted_ids = set(request.voter.votes.values_list("election_id", flat=True))
    return render(request, "elections/voter_dashboard.html", {"voter": request.voter, "active_elections": [e for e in elections if e.is_open_for_voting], "voted_ids": voted_ids})
