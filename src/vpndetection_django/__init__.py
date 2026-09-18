"""Official Django middleware for the VPNDetection API.

Classifies the visitor behind each request and hangs the answer off
``request.vpndetection``, where your views can read it. Blocking is opt-in.

    # settings.py
    MIDDLEWARE = [..., "vpndetection_django.VPNDetectionMiddleware"]
    VPNDETECTION = {"api_key": os.environ["VPNDETECTION_API_KEY"]}

The framework-agnostic half lives in ``vpndetection.middleware``; this package is
only the parts that are genuinely Django-shaped.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from django.conf import settings
from django.http import HttpRequest, HttpResponse, JsonResponse
from vpndetection.middleware import (
    Core,
    IpSelector,
    Lookup,
    Options,
    RequestView,
    Selectors,
    bind_selectors,
)

__all__ = [
    "VPNDetectionMiddleware",
    "default_ip_selector",
    "header_ip_selector",
    "xff_ip_selector",
]

__version__ = "2.0.2"

_SELECTORS: Selectors[HttpRequest] = bind_selectors(
    lambda request: RequestView(
        header=lambda name: request.headers.get(name),
        framework_ip=lambda: request.META.get("REMOTE_ADDR"),
    )
)

#: ``REMOTE_ADDR``, which is the socket peer.
#:
#: Django deliberately does NOT read ``X-Forwarded-For`` for you - it removed
#: ``SECURE_PROXY_SSL_HEADER``'s address equivalent precisely because trusting a header
#: without knowing your topology is unsafe. So behind a load balancer this is the load
#: balancer, a datacenter address a hosting rule would block every visitor for. If you
#: are behind one, use :func:`header_ip_selector` or :func:`xff_ip_selector`.
default_ip_selector: IpSelector[HttpRequest] = _SELECTORS.default

#: An address from ``X-Forwarded-For``.
#:
#: The LEFT-MOST entry (``depth`` 0) is whatever the caller sent, because proxies
#: append to this header, so a visitor who sets it themselves appears first and this
#: returns their forgery. It is only trustworthy when an edge you control overwrites
#: the header. When you know how many proxies sit in front, count from the right:
#: ``xff_ip_selector(1)`` is the address your nearest proxy saw.
xff_ip_selector = _SELECTORS.xff

#: An address from a single-value header your edge writes -
#: ``header_ip_selector("CF-Connecting-IP")`` behind Cloudflare. Falls back to
#: ``REMOTE_ADDR`` when the header is absent.
header_ip_selector = _SELECTORS.header


class VPNDetectionMiddleware:
    """Classify the visitor, and optionally refuse the request.

    Configured from ``settings.VPNDETECTION``, a dict taking everything
    :class:`vpndetection.middleware.Options` does plus ``on_blocked``.

    Without a ``block_condition`` this only enriches the request and never refuses
    one, leaving the decision to your own views. A lookup that fails - network, quota,
    an outage of ours - lets the request through and records why on
    ``request.vpndetection.error``, unless you set ``fail_closed``.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]) -> None:
        configured: dict[str, Any] = dict(getattr(settings, "VPNDETECTION", {}) or {})
        self._on_blocked: Callable[[HttpRequest, Lookup], HttpResponse] = configured.pop(
            "on_blocked", _refuse
        )
        self._core: Core[HttpRequest] = Core(Options(**configured), default_ip_selector)
        self._get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        lookup = self._core.evaluate(request)
        if lookup is None:
            return self._get_response(request)
        request.vpndetection = lookup
        if lookup.blocked:
            return self._on_blocked(request, lookup)
        return self._get_response(request)


def _refuse(_request: HttpRequest, _lookup: Lookup) -> HttpResponse:
    return JsonResponse({"error": "access denied"}, status=403)
