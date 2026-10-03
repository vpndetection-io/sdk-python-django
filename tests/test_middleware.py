"""The adapter, through a real Django request cycle, plus the shared corpus.

A test client connects from ``127.0.0.1``, which is a bogon and is answered locally
without a request. Anything that needs a served answer therefore has to arrive wearing
a public address, through a selector.
"""

from __future__ import annotations

import json
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
