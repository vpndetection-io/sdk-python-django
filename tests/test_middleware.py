"""The adapter, through a real Django request cycle, plus the shared corpus.

A test client connects from ``127.0.0.1``, which is a bogon and is answered locally
without a request. Anything that needs a served answer therefore has to arrive wearing
a public address, through a selector.
"""

from __future__ import annotations

import json
import os
import pathlib
from typing import Any

import django
import httpx
import pytest
from django.conf import settings

PUBLIC_IP = "45.83.91.1"

settings.configure(
    DEBUG=True,
    SECRET_KEY="test",
    ALLOWED_HOSTS=["*"],
    ROOT_URLCONF=__name__,
    MIDDLEWARE=["vpndetection_django.VPNDetectionMiddleware"],
    DATABASES={},
    VPNDETECTION={},
)
django.setup()

from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, JsonResponse
from django.test import Client, RequestFactory
from django.urls import path
from vpndetection import VPNDetection

from vpndetection_django import (
    VPNDetectionMiddleware,
    block_if,
    default_ip_selector,
    header_ip_selector,
    lookup,
    xff_ip_selector,
)

CORPUS = json.loads(
    (pathlib.Path(__file__).parent.parent / "testdata/testdata.json").read_text()
)
MIDDLEWARE = CORPUS["middleware"]


def view(request: Any) -> JsonResponse:
    found = lookup(request)
    return JsonResponse(
        {
            "ip": found.ip if found else None,
            "is_vpn": found.result.is_vpn if found and found.result else None,
            "is_bogon": found.result.is_bogon if found and found.result else None,
            "error": type(found.error).__name__ if found and found.error else None,
            "attached": found is not None,
        }
    )


@block_if({"is_vpn": True})
def guarded(request: Any) -> JsonResponse:
    return view(request)


@block_if({"is_vpn": True})
async def guarded_async(request: Any) -> JsonResponse:
    return view(request)


@block_if(
    {"is_vpn": True},
    on_blocked=lambda request, found: JsonResponse(
        {"why": found.result.vpn.provider}, status=451
    ),
)
def guarded_custom(request: Any) -> JsonResponse:
    return view(request)


@block_if({"is_vpn": True}, fail_closed=True)
def guarded_closed(request: Any) -> JsonResponse:
    return view(request)


# The corpus through the decorator: each case sets the condition, and the guard is
# built per request so its warn-once starts clean.
CASE: dict[str, Any] = {}


def corpus(request: Any) -> JsonResponse:
    return block_if(CASE["condition"], on_warn=CASE["warnings"].append)(view)(request)  # type: ignore[no-any-return]


urlpatterns = [
    path("", view),
    path("guarded", guarded),
    path("guarded-async", guarded_async),
    path("guarded-custom", guarded_custom),
    path("guarded-closed", guarded_closed),
    path("corpus", corpus),
]


def serving(body: dict[str, Any], *, status: int = 200) -> VPNDetection:
    """A client whose every answer is ``body``, recording what it was asked about."""

    def handle(request: httpx.Request) -> httpx.Response:
        ip = request.url.path.lstrip("/")
        asked.append(ip)
        return httpx.Response(status, json={"ip": ip, **body})

    asked: list[str] = []
    client = VPNDetection(cache=False, retries=0, transport=httpx.MockTransport(handle))
    client.asked = asked  # type: ignore[attr-defined]
    return client


def call(headers: dict[str, str] | None = None, **options: Any) -> Any:
    settings.VPNDETECTION = options
    return Client(
        **{f"HTTP_{k.upper().replace('-', '_')}": v for k, v in (headers or {}).items()}
    )


def get(client: Any, url: str = "/") -> tuple[int, dict[str, Any]]:
    response = client.get(url)
    return response.status_code, json.loads(response.content or b"{}")


def fixed_ip(_request: Any) -> str:
    return PUBLIC_IP


def test_enriches_the_request_and_leaves_the_decision_to_the_app() -> None:
    client = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    status, body = get(call(client=client, ip_selector=fixed_ip))
    assert status == 200
    assert body["attached"] is True
    assert body["is_vpn"] is True
    assert body["ip"] == PUBLIC_IP
    assert client.asked == [PUBLIC_IP]


def test_blocks_when_the_condition_matches_and_passes_when_it_does_not() -> None:
    vpn = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    status, body = get(call(client=vpn, ip_selector=fixed_ip, block_condition={"is_vpn": True}))
    assert status == 403
    assert body == {"error": "access denied"}
    assert body.get("attached") is None, "the view answered a blocked request"

    clean = serving({"is_vpn": False, "vpn": {}})
    status, _ = get(call(client=clean, ip_selector=fixed_ip, block_condition={"is_vpn": True}))
    assert status == 200


@pytest.mark.parametrize("condition", [{"is_bot": True}, {"bot": {"verified": True}}])
def test_a_condition_on_a_bot_blocks_a_bot_and_passes_the_rest(
    condition: dict[str, Any],
) -> None:
    for is_bot, bot in ((True, {"provider": "google", "verified": True}), (False, {})):
        served = serving({"is_vpn": False, "is_bot": is_bot, "bot": bot})
        status, _ = get(call(client=served, ip_selector=fixed_ip, block_condition=condition))
        assert status == (403 if is_bot else 200), f"{condition} against is_bot {is_bot}"
        assert served.asked == [PUBLIC_IP]


ASN = {
    "asn": 9009,
    "name": "M247 Europe SRL",
    "domain": "m247global.com",
    "prefix": "146.70.116.0/24",
    "country": "US",
    "rpki_status": "valid",
}


def test_an_answer_without_the_asn_type_is_read_and_a_condition_on_it_never_matches() -> None:
    warnings: list[str] = []
    keyless = serving({"is_vpn": True, "asn": ASN})
    status, body = get(
        call(
            client=keyless,
            ip_selector=fixed_ip,
            block_condition={"asn": {"type": "hosting"}},
            on_warn=warnings.append,
        )
    )
    assert status == 200
    assert body["error"] is None and body["is_vpn"] is True, "the answer was read and attached"
    reported = [w for w in warnings if "does not include" in w]
    assert len(reported) == 1 and "asn.type" in reported[0]

    paid = serving({"is_vpn": True, "asn": {**ASN, "type": "hosting"}})
    status, _ = get(
        call(client=paid, ip_selector=fixed_ip, block_condition={"asn": {"type": "hosting"}})
    )
    assert status == 403, "the same condition blocks an answer that carries the type"


def test_a_condition_reaches_the_evidence_fields() -> None:
    nord = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    status, _ = get(
        call(
            client=nord, ip_selector=fixed_ip, block_condition={"vpn": {"provider": "mullvad"}}
        )
    )
    assert status == 200, "a different provider must not match"

    mullvad = serving({"is_vpn": True, "vpn": {"provider": "MULLVAD"}})
    status, _ = get(
        call(
            client=mullvad,
            ip_selector=fixed_ip,
            block_condition={"vpn": {"provider": "mullvad"}},
        )
    )
    assert status == 403, "a provider must compare without case"


def test_on_blocked_replaces_the_refusal() -> None:
    client = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    status, body = get(
        call(
            client=client,
            ip_selector=fixed_ip,
            block_condition={"is_vpn": True},
            on_blocked=lambda request, found: JsonResponse(
                {"why": found.result.vpn.provider}, status=451
            ),
        )
    )
    assert status == 451
    assert body == {"why": "nordvpn"}


def test_skip_leaves_the_request_untouched() -> None:
    client = serving({"is_vpn": True})
    status, body = get(
        call(
            client=client,
            ip_selector=fixed_ip,
            block_condition={"is_vpn": True},
            skip=lambda request: request.path == "/",
        )
    )
    assert status == 200
    assert body["attached"] is False
    assert client.asked == []


def test_lookup_is_the_attached_answer_or_none() -> None:
    """``request.vpndetection`` exists only on a request the middleware classified, so a
    view reading it where ``skip`` applies raised ``AttributeError``, a 500."""
    request = HttpRequest()
    assert lookup(request) is None
    request.vpndetection = found = object()  # type: ignore[attr-defined]
    assert lookup(request) is found


def test_a_failing_lookup_lets_the_visitor_through() -> None:
    failing = serving({"error": "boom"}, status=500)
    status, body = get(
        call(client=failing, ip_selector=fixed_ip, block_condition={"is_vpn": True})
    )
    assert status == 200
    assert body["error"] == "VPNDetectionError"


# The test that matters. Every other assertion here would pass whether or not the
# selector is right, because a direct connection has nothing to confuse.
def test_a_forged_x_forwarded_for_is_ignored_by_default() -> None:
    client = serving({"is_vpn": True})
    _, body = get(call({"X-Forwarded-For": PUBLIC_IP}, client=client))
    assert body["ip"] == "127.0.0.1", "REMOTE_ADDR is the socket peer; the header is a forgery"
    assert client.asked == [], "and a bogon is answered locally, so nothing was asked"

    explicit = serving({"is_vpn": True})
    _, body = get(
        call({"X-Forwarded-For": PUBLIC_IP}, client=explicit, ip_selector=xff_ip_selector())
    )
    assert body["ip"] == PUBLIC_IP
    assert explicit.asked == [PUBLIC_IP]


def test_a_header_selector_reads_the_edge_that_writes_it() -> None:
    client = serving({"is_vpn": True})
    _, body = get(
        call(
            {"CF-Connecting-IP": "45.83.91.9"},
            client=client,
            ip_selector=header_ip_selector("CF-Connecting-IP"),
        )
    )
    assert body["ip"] == "45.83.91.9"
    assert client.asked == ["45.83.91.9"]


def test_depth_counts_trusted_hops_from_the_right() -> None:
    client = serving({"is_vpn": True})
    get(
        call(
            {"X-Forwarded-For": f"{PUBLIC_IP}, 70.41.3.18, 150.172.238.178"},
            client=client,
            ip_selector=xff_ip_selector(1),
        )
    )
    assert client.asked == ["150.172.238.178"]


def test_a_private_client_address_is_answered_locally_and_never_blocks() -> None:
    client = serving({"is_vpn": True})
    status, body = get(
        call(client=client, block_condition={"is_vpn": True}, ip_selector=default_ip_selector)
    )
    assert status == 200, "local development must not lock you out of your own app"
    assert body["is_bogon"] is True
    assert client.asked == []


def test_a_condition_that_constrains_nothing_is_refused_at_construction() -> None:
    settings.VPNDETECTION = {"block_condition": {"is_vpn": False}}
    with pytest.raises(ValueError, match="constrains nothing"):
        VPNDetectionMiddleware(lambda request: JsonResponse({}))


@pytest.mark.parametrize("case", MIDDLEWARE["conditions"], ids=lambda c: c["name"])
def test_corpus_conditions(case: dict[str, Any]) -> None:
    ip = case.get("bogon") or case["body"]["ip"]
    client = serving({k: v for k, v in (case.get("body") or {}).items() if k != "ip"})
    warnings: list[str] = []
    status, _ = get(
        call(
            client=client,
            ip_selector=lambda _request, ip=ip: ip,
            block_condition=case["condition"],
            on_warn=warnings.append,
        )
    )
    assert status == (403 if case["expect"]["blocked"] else 200), case["why"]
    reported = [w for w in warnings if "does not include" in w]
    assert len(reported) == (1 if case["expect"]["missing"] else 0), case["why"]
    for member in case["expect"]["missing"]:
        assert member in reported[0], case["why"]


def test_block_if_refuses_only_the_view_it_decorates() -> None:
    vpn = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    browser = call(client=vpn, ip_selector=fixed_ip)
    status, body = get(browser, "/guarded")
    assert status == 403
    assert body == {"error": "access denied"}
    status, body = get(browser, "/")
    assert status == 200, "the middleware itself has no condition, so other views are open"
    assert body["is_vpn"] is True
    assert vpn.asked == [PUBLIC_IP, PUBLIC_IP], "one lookup per request, none by the decorator"

    clean = serving({"is_vpn": False, "vpn": {}})
    status, body = get(call(client=clean, ip_selector=fixed_ip), "/guarded")
    assert status == 200
    assert body["attached"] is True


def test_block_if_guards_an_async_view() -> None:
    vpn = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    status, body = get(call(client=vpn, ip_selector=fixed_ip), "/guarded-async")
    assert status == 403
    assert body == {"error": "access denied"}

    clean = serving({"is_vpn": False, "vpn": {}})
    status, _ = get(call(client=clean, ip_selector=fixed_ip), "/guarded-async")
    assert status == 200


def test_block_if_on_blocked_replaces_the_refusal() -> None:
    vpn = serving({"is_vpn": True, "vpn": {"provider": "nordvpn"}})
    status, body = get(call(client=vpn, ip_selector=fixed_ip), "/guarded-custom")
    assert status == 451
    assert body == {"why": "nordvpn"}


def test_block_if_lets_a_skipped_request_through() -> None:
    vpn = serving({"is_vpn": True})
    status, body = get(
        call(client=vpn, ip_selector=fixed_ip, skip=lambda request: True), "/guarded"
    )
    assert status == 200
    assert body["attached"] is False
    assert vpn.asked == []


def test_block_if_fails_open_unless_told_to_fail_closed() -> None:
    failing = serving({"error": "boom"}, status=500)
    status, body = get(call(client=failing, ip_selector=fixed_ip), "/guarded")
    assert status == 200
    assert body["error"] == "VPNDetectionError"

    status, body = get(call(client=failing, ip_selector=fixed_ip), "/guarded-closed")
    assert status == 403
    assert body == {"error": "access denied"}


def test_block_if_without_the_middleware_is_a_configuration_error() -> None:
    request = RequestFactory().get("/guarded")
    with pytest.raises(ImproperlyConfigured, match="VPNDetectionMiddleware"):
        guarded(request)


def test_block_if_refuses_a_condition_that_constrains_nothing() -> None:
    with pytest.raises(ValueError, match="constrains nothing"):
        block_if({"is_vpn": False})(view)


def test_block_if_warns_once_naming_the_view() -> None:
    free = serving({"is_vpn": True})
    warnings: list[str] = []

    @block_if({"is_hosting": True}, on_warn=warnings.append)
    def hosted(request: Any) -> JsonResponse:
        return view(request)

    settings.VPNDETECTION = {"client": free, "ip_selector": fixed_ip}
    for _ in range(2):
        request = RequestFactory().get("/")
        VPNDetectionMiddleware(hosted)(request)
    assert len(warnings) == 1
    assert "block_if on test_block_if_warns_once_naming_the_view.<locals>.hosted" in warnings[0]
    assert "is_hosting" in warnings[0]


@pytest.mark.parametrize("case", MIDDLEWARE["conditions"], ids=lambda c: c["name"])
def test_corpus_conditions_through_block_if(case: dict[str, Any]) -> None:
    ip = case.get("bogon") or case["body"]["ip"]
    client = serving({k: v for k, v in (case.get("body") or {}).items() if k != "ip"})
    CASE.update(condition=case["condition"], warnings=[])
    status, _ = get(call(client=client, ip_selector=lambda _request, ip=ip: ip), "/corpus")
    assert status == (403 if case["expect"]["blocked"] else 200), case["why"]
    reported = [w for w in CASE["warnings"] if "does not include" in w]
    assert len(reported) == (1 if case["expect"]["missing"] else 0), case["why"]
    for member in case["expect"]["missing"]:
        assert member in reported[0], case["why"]


# Built exactly as the README builds it: an API key and nothing else. Every other test hands
# the middleware a client, so none of them could see a core that cannot start from a key
# alone. The test client's loopback peer is a bogon, answered with no request.
def test_the_middleware_starts_the_way_the_readme_builds_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("VPNDETECTION_API_KEY", "a-key")
    status, body = get(call(api_key=os.environ["VPNDETECTION_API_KEY"]))

    assert status == 200
    assert body["attached"] is True
    assert body["is_bogon"] is True
    assert body["error"] is None


# The README's middleware again, served a PUBLIC peer with a forged X-Forwarded-For: the key must
# reach the API, and the socket address must be the one looked up. The test above is answered
# with no request, so it passed with the key dropped. httpx's own transport answers for the
# API's host alone, so nothing leaves the machine.
def test_the_readme_middleware_sends_its_key_for_a_public_peer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[tuple[str, str | None]] = []

    def handle(_transport: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.vpndetection.io":
            raise httpx.ConnectError("only the API's host answers here", request=request)
        sent.append((request.url.path, request.headers.get("Authorization")))
        return httpx.Response(200, json={"ip": PUBLIC_IP, "is_vpn": True})

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)
    monkeypatch.setenv("VPNDETECTION_API_KEY", "a-key")
    client = call({"X-Forwarded-For": "1.1.1.1"}, api_key=os.environ["VPNDETECTION_API_KEY"])
    response = client.get("/", REMOTE_ADDR=PUBLIC_IP)
    status, body = response.status_code, json.loads(response.content)

    assert status == 200
    assert body["ip"] == PUBLIC_IP, "the socket peer is looked up; the header is a forgery"
    assert body["error"] is None and body["is_vpn"] is True
    assert len(sent) == 1 and sent[0][0].endswith(PUBLIC_IP)
    assert sent[0][1] == "Bearer a-key"


GOOGLEBOT = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"


@block_if({"is_hosting": True})
def guarded_hosting(request: Any) -> JsonResponse:
    return view(request)


urlpatterns.append(path("guarded-hosting", guarded_hosting))


@block_if({"user_agent": {"verdict": "spoofed"}}, on_missing_field="raise")
def guarded_forged(request: Any) -> JsonResponse:
    return view(request)


urlpatterns.append(path("guarded-forged", guarded_forged))


def api_answering(
    monkeypatch: pytest.MonkeyPatch, verdicts: dict[str, str] | None
) -> list[str | None]:
    """The API's host, answering every lookup as a match for ``{"is_hosting": True}`` and,
    for a sent agent, with the verdict ``verdicts`` holds for it (None: no verdict, as
    Unlimited answers). Returns the ``user_agent`` each lookup sent."""
    sent: list[str | None] = []

    def handle(_transport: httpx.HTTPTransport, request: httpx.Request) -> httpx.Response:
        if request.url.host != "api.vpndetection.io":
            raise httpx.ConnectError("only the API's host answers here", request=request)
        agent = request.url.params.get("user_agent")
        sent.append(agent)
        body: dict[str, Any] = {
            "ip": request.url.path.lstrip("/"),
            "is_vpn": False,
            "is_hosting": True,
        }
        if agent and verdicts is not None:
            verdict = verdicts.get(agent, "not_bot")
            body["user_agent"] = {"agent": "Googlebot", "kind": "bot", "verdict": verdict}
        return httpx.Response(200, json=body)

    monkeypatch.setattr(httpx.HTTPTransport, "handle_request", handle)
    monkeypatch.setenv("VPNDETECTION_API_KEY", "a-key")
    return sent


def visit(user_agent: str | None, url: str = "/", peer: str = PUBLIC_IP, **options: Any) -> int:
    """One request through the README's settings, plus ``options``."""
    headers = {} if user_agent is None else {"User-Agent": user_agent}
    client = call(headers, api_key=os.environ["VPNDETECTION_API_KEY"], **options)
    return int(client.get(url, REMOTE_ADDR=peer).status_code)


def test_allow_bots_sends_the_requests_own_user_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent = api_answering(monkeypatch, {GOOGLEBOT: "verified"})

    visit(GOOGLEBOT, allow_bots=True)
    visit("", peer="45.83.91.2", allow_bots=True)
    visit(None, peer="45.83.91.3", allow_bots=True)

    assert sent == [GOOGLEBOT, None, None], "an empty or absent header sent an agent"


def test_without_allow_bots_no_user_agent_is_sent(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = api_answering(monkeypatch, {GOOGLEBOT: "verified"})

    status = visit(GOOGLEBOT, block_condition={"is_hosting": True})

    assert sent == [None]
    assert status == 403


@pytest.mark.parametrize(
    ("verdict", "status"), [("verified", 200), ("spoofed", 403), ("not_bot", 403)]
)
@pytest.mark.parametrize("url", ["/", "/guarded-hosting"])
def test_a_verified_crawler_passes_a_condition_it_meets_and_no_other_does(
    monkeypatch: pytest.MonkeyPatch, url: str, verdict: str, status: int
) -> None:
    api_answering(monkeypatch, {GOOGLEBOT: verdict})
    options: dict[str, Any] = {"allow_bots": True}
    if url == "/":
        options["block_condition"] = {"is_hosting": True}

    assert visit(GOOGLEBOT, url=url, **options) == status


def test_a_condition_naming_the_verdict_refuses_a_forged_crawler(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    api_answering(monkeypatch, {GOOGLEBOT: "spoofed"})

    status = visit(
        GOOGLEBOT, allow_bots=True, block_condition={"user_agent": {"verdict": "spoofed"}}
    )

    assert status == 403


def test_an_answer_without_a_verdict_warns_once(monkeypatch: pytest.MonkeyPatch) -> None:
    sent = api_answering(monkeypatch, None)
    warnings: list[str] = []
    settings.VPNDETECTION = {
        "api_key": os.environ["VPNDETECTION_API_KEY"],
        "allow_bots": True,
        "on_warn": warnings.append,
    }
    client = Client(HTTP_USER_AGENT=GOOGLEBOT)

    client.get("/", REMOTE_ADDR=PUBLIC_IP)
    client.get("/", REMOTE_ADDR="45.83.91.2")

    assert sent == [GOOGLEBOT, GOOGLEBOT]
    assert len([w for w in warnings if "user_agent verdict" in w]) == 1, warnings


@pytest.mark.parametrize("url", ["/", "/guarded-forged"])
@pytest.mark.parametrize("action", ["raise", "warn"])
@pytest.mark.parametrize("peer", ["127.0.0.1", "10.0.0.1", "::1"])
def test_a_bogon_peer_with_a_crawlers_agent_is_no_plan_gap(
    monkeypatch: pytest.MonkeyPatch, peer: str, action: str, url: str
) -> None:
    # Local development behind no proxy. This is NOT the public-peer test above: the peer is
    # answered locally, so the question is only that no plan gap is reported for it.
    sent = api_answering(monkeypatch, {GOOGLEBOT: "spoofed"})
    warnings: list[str] = []
    forged = {"user_agent": {"verdict": "spoofed"}}
    options: dict[str, Any] = {
        "allow_bots": True,
        "on_missing_field": action,
        "on_warn": warnings.append,
    }
    if url == "/":
        options["block_condition"] = forged

    assert visit(GOOGLEBOT, url=url, peer=peer, **options) == 200
    assert sent == [], "a bogon reached the API"
    assert [w for w in warnings if "does not include" in w] == []
