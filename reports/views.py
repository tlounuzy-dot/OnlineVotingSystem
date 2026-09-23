import csv
from django.http import HttpResponse
from django.shortcuts import render
from django.utils import timezone
from accounts.models import AuditLog
from accounts.permissions import admin_required, verified_voter_required
from elections.models import Election
from voting.models import Vote


def _result_context(elections):
    items = []
    for election in elections.prefetch_related("results__candidate"):
        results = list(election.results.select_related("candidate"))
        items.append({"election": election, "results": results, "total_votes": sum(row.total_votes for row in results)})
    return items


@verified_voter_required
def voter_results(request):
    elections = Election.objects.filter(
        results_published_at__isnull=False,
        end_date__lte=timezone.now(),
    ).exclude(status=Election.Status.CANCELLED)
    return render(request, "reports/results.html", {"election_results": _result_context(elections), "admin_view": False})


@admin_required
def admin_results(request):
    return render(request, "reports/results.html", {"election_results": _result_context(Election.objects.all()), "admin_view": True})


@admin_required
def report_list(request):
    participation = [{"election": election, "votes": Vote.objects.filter(election=election).count()} for election in Election.objects.all()]
    AuditLog.objects.create(user=request.user, action="report_viewed", description="Administrative reports viewed.")
    return render(request, "reports/report_list.html", {"participation": participation})


@admin_required
def export_csv(request):
    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = 'attachment; filename="election-report.csv"'
    writer = csv.writer(response); writer.writerow(["Election", "Status", "Candidate", "Votes", "Percentage"])
    for item in _result_context(Election.objects.all()):
        for result in item["results"]: writer.writerow([item["election"].title, item["election"].calculated_status, result.candidate.full_name, result.total_votes, result.percentage])
    AuditLog.objects.create(user=request.user, action="report_exported", description="Election report exported as CSV.")
    return response


@admin_required
def audit_logs(request):
    return render(request, "reports/audit_logs.html", {"logs": AuditLog.objects.select_related("user")[:250]})
