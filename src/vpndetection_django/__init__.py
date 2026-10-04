"""Official Django middleware for the VPNDetection API.

Classifies the visitor behind each request and hangs the answer off
``request.vpndetection``, where your views can read it. Blocking is opt-in, for every
view in ``settings.VPNDETECTION`` or for one with :func:`block_if`.

    # settings.py
    MIDDLEWARE = [..., "vpndetection_django.VPNDetectionMiddleware"]
    VPNDETECTION = {"api_key": os.environ["VPNDETECTION_API_KEY"]}

The framework-agnostic half lives in ``vpndetection.middleware``; this package is
only the parts that are genuinely Django-shaped.
"""

from __future__ import annotations

from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar

from asgiref.sync import iscoroutinefunction
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest, HttpResponse, JsonResponse
from vpndetection.middleware import (
    Conditions,
    Core,
    Guard,
    IpSelector,
    Lookup,
    MissingFieldAction,
    Options,
    RequestView,
    Selectors,
    bind_selectors,
)

__all__ = [
    "VPNDetectionMiddleware",
    "block_if",
    "default_ip_selector",
    "header_ip_selector",
    "lookup",
    "xff_ip_selector",
]

__version__ = "2.2.1"

View = TypeVar("View", bound=Callable[..., Any])

# Set on a request ``skip`` claimed, so block_if can tell it from one the middleware
# never saw.
_SKIPPED = "_vpndetection_skipped"

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


def lookup(request: HttpRequest) -> Lookup | None:
    """What the middleware found out about this visitor.

    None when the middleware has not run for this request, or when ``skip`` claimed it:
    only a request it classified carries ``request.vpndetection``, so reading that
    attribute on one ``skip`` claimed raises ``AttributeError``.
    """
    return getattr(request, "vpndetection", None)


def block_if(
    condition: Conditions,
    *,
    on_blocked: Callable[[HttpRequest, Lookup], HttpResponse] | None = None,
    fail_closed: bool = False,
    on_missing_field: MissingFieldAction = "warn",
    on_warn: Callable[[str], None] | None = None,
) -> Callable[[View], View]:
    """Refuse one view to a visitor matching ``condition``.

    The middleware's ``block_condition`` refuses on every view; this refuses on the view
    it decorates, sync or async::

        @block_if({"is_vpn": True})
        def checkout(request): ...

    It judges the answer the middleware already attached, so the visitor is not looked
    up again, and a member your plan does not serve is reported once, as the
    middleware's own condition reports it. A condition that constrains nothing is
    refused when the decorator is applied.

    A request ``skip`` claimed carries no answer and reaches the view, and so does one
    whose lookup failed unless you set ``fail_closed``. A request the middleware never
    saw raises ``ImproperlyConfigured``: a check that silently never ran would be worse
    than none.
    """
    refuse = on_blocked or _refuse

    def decorate(view: View) -> View:
        guard = Guard(
            condition,
            fail_closed=fail_closed,
            on_missing_field=on_missing_field,
            on_warn=on_warn,
            name=f"block_if on {getattr(view, '__qualname__', view)}",
        )

        def refusal(request: HttpRequest) -> HttpResponse | None:
            found = lookup(request)
            if found is None:
                if getattr(request, _SKIPPED, False):
                    return None
                raise ImproperlyConfigured(
                    "vpndetection: block_if found no answer on this request; add "
                    "vpndetection_django.VPNDetectionMiddleware to MIDDLEWARE"
                )
            return refuse(request, found) if guard.blocks(found) else None

        if iscoroutinefunction(view):

            @wraps(view)
            async def guarded_async(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
                refused = refusal(request)
                if refused is not None:
                    return refused
                return await view(request, *args, **kwargs)

            return guarded_async  # type: ignore[return-value]

        @wraps(view)
        def guarded(request: HttpRequest, *args: Any, **kwargs: Any) -> Any:
            refused = refusal(request)
            if refused is not None:
                return refused
            return view(request, *args, **kwargs)

        return guarded  # type: ignore[return-value]

    return decorate


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
            setattr(request, _SKIPPED, True)
            return self._get_response(request)
        request.vpndetection = lookup
        if lookup.blocked:
            return self._on_blocked(request, lookup)
        return self._get_response(request)


def _refuse(_request: HttpRequest, _lookup: Lookup) -> HttpResponse:
    return JsonResponse({"error": "access denied"}, status=403)
