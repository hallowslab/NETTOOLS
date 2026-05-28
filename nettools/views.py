from django.contrib.auth.decorators import login_required
from django.shortcuts import render

from .services.whereis import lookup_domains
from .services.whois import lookup_whois
from .services.spf import lookup_spf
from .services.propagation import lookup_propagation


NETTOOLS_FUNCTIONS = [
    {
        "name": "WhereIs",
        "description": "Bulk domain DNS lookup for A, MX, MX host A, and reverse DNS records.",
        "url_name": "nettools:whereis",
        "status": "Available",
    },
    {
        "name": "WHOIS Lookup",
        "description": "Retrieve domain registrar, expiration date, and registrar delegation name servers.",
        "url_name": "nettools:whois",
        "status": "Available",
    },
    {
        "name": "SPF Lookup",
        "description": "Fetch SPF records, parse policies, check for multiple SPF records, and highlight qualifiers.",
        "url_name": "nettools:spf",
        "status": "Available",
    },
    {
        "name": "DNS Propagation Checker",
        "description": "Check domain resolution propagation consistency across global public resolvers.",
        "url_name": "nettools:propagation",
        "status": "Available",
    },
]


@login_required
def index(request):
    return render(
        request,
        "nettools_index.html",
        {"functions": NETTOOLS_FUNCTIONS},
    )


@login_required
def whereis(request):
    domains = ""
    lookup_result = None

    if request.method == "POST":
        domains = request.POST.get("domains", "")
        lookup_result = lookup_domains(domains)

    return render(
        request,
        "nettools/whereis.html",
        {
            "domains": domains,
            "lookup_result": lookup_result,
        },
    )


@login_required
def whois(request):
    domains = ""
    lookup_result = None

    if request.method == "POST":
        domains = request.POST.get("domains", "")
        lookup_result = lookup_whois(domains)

    return render(
        request,
        "nettools/whois.html",
        {
            "domains": domains,
            "lookup_result": lookup_result,
        },
    )


@login_required
def spf(request):
    domains = ""
    lookup_result = None

    if request.method == "POST":
        domains = request.POST.get("domains", "")
        lookup_result = lookup_spf(domains)

    return render(
        request,
        "nettools/spf.html",
        {
            "domains": domains,
            "lookup_result": lookup_result,
        },
    )


@login_required
def propagation(request):
    domains = ""
    lookup_result = None

    if request.method == "POST":
        domains = request.POST.get("domains", "")
        lookup_result = lookup_propagation(domains)

    return render(
        request,
        "nettools/propagation.html",
        {
            "domains": domains,
            "lookup_result": lookup_result,
        },
    )
