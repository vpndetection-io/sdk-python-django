# [<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="28"/>](https://vpndetection.io/) VPNDetection Django Middleware

[![PyPI](https://img.shields.io/pypi/v/vpndetection-django.svg)](https://pypi.org/project/vpndetection-django/)
[![license](https://img.shields.io/pypi/l/vpndetection-django.svg)](LICENSE)

The official Django middleware for the [VPNDetection](https://vpndetection.io) API: it checks each visitor's IP for VPN, Tor and proxy use, and can block them with a 403.

It classifies the visitor behind each request: VPN, residential proxy, Tor, hosting, CDN or relay. Then it hands the answer to your code. Blocking is opt-in.

## Getting Started

```bash
pip install vpndetection-django
```

Requires Python 3.11 or newer.

No API key needed to start. Without one, a lookup is on Unlimited, the free plan, which answers VPN, Tor and relay detection with no daily or monthly cap. A paid plan's key adds the hosting, CDN and proxy flags and the provider behind each flag: create one in the [console](https://app.vpndetection.io). A free account tries every field.

Add it to `MIDDLEWARE` and configure it with a `VPNDETECTION` dict:

```python
# settings.py
MIDDLEWARE = [
    # ...
    "vpndetection_django.VPNDetectionMiddleware",
]

VPNDETECTION = {"api_key": os.environ["VPNDETECTION_API_KEY"]}
```

```python
def index(request):
    found = request.vpndetection
    return HttpResponse("Hello, VPN user" if found.result.is_vpn else "Hello")
```

A request your `skip` claims gets no answer, so it carries no `request.vpndetection`. Wherever `skip` can apply, read the answer as `lookup(request)`, imported from `vpndetection_django`, which is `None` for such a request.

By default nothing is blocked. Every request gets an answer and your own code decides what to do with it, since whether a VPN visitor is a problem depends on what they're doing.

## Blocking

Pass a `block_condition` and a matching request is answered with `403` and never reaches your code.

```python
block_condition = {"is_vpn": True}
```

A condition is written in the shape of a result, keyed by the same names the API uses, and only the members you name are considered. That lets it reach the evidence, not just the flags:

```python
{"is_vpn": True, "vpn": {"provider": "nordvpn"}}  # one provider
{"is_resproxy": True, "resproxy": {"hits": {"gte": 5}}}  # a numeric threshold
{"vpn": {"confidence": ["high", "medium"]}}  # any of these
[{"is_tor": True}, {"is_resproxy": True}]  # a list is OR
```

Values are matched by equality, strings without regard to case. A list means any-of. A dict of `gte`/`gt`/`lte`/`lt` compares numbers, and every bound you give must hold, so two of them are a range. Members set to `False` or `None` are ignored, so a condition states the signals you act on; one that constrains nothing would match every request, and is refused when the middleware is built rather than silently blocking all your traffic.

Replace the refusal with `on_blocked`.

### Blocking one view

`block_condition` applies to every view. To refuse a visitor on some views only, decorate them, sync or async:

```python
from vpndetection_django import block_if


@block_if({"is_vpn": True})
def checkout(request): ...
```

`block_if` takes the same condition, `on_blocked`, `fail_closed` and `on_missing_field`. It judges the answer the middleware already attached, so a visitor is looked up once however many views check them, and it warns once for a member your plan doesn't include. A request `skip` claimed reaches the view. The middleware still has to be installed: without it, a decorated view raises `ImproperlyConfigured` instead of letting everyone through.

## Where the client address comes from

Get this setting right, or none of the above works.

By default the middleware uses `REMOTE_ADDR`, which is the socket peer. **Django deliberately does not read `X-Forwarded-For` for you**, because trusting a header without knowing your topology is unsafe. So if your app sits behind nginx, a load balancer, or a CDN, every visitor arrives wearing your proxy's address, and that is the address that gets checked: VPN visitors pass unnoticed, and if it is a hosting address, a hosting rule blocks everyone. nginx on the same machine is `127.0.0.1` and a load balancer usually has a private address, which the middleware answers locally without a lookup, flagging nobody and logging a warning.

For an edge that writes the address into its own header, name the header:

```python
from vpndetection_django import header_ip_selector

ip_selector = header_ip_selector("CF-Connecting-IP")  # or True-Client-IP, or your own
```

`xff_ip_selector()` reads `X-Forwarded-For` directly. The left-most entry is whatever the caller sent, since proxies append to that header, so trust it only when an edge you control overwrites it. If you know how many proxies sit in front, count from the right instead: `xff_ip_selector(1)` is the address your nearest proxy saw.

Anything else, pass your own callable. It receives the request and returns an address.

If the address resolves to a private one, the middleware says so once through the `vpndetection` logger. That is expected on localhost and is the signal to fix your configuration anywhere else.

## When a lookup fails

The request is let through, and the reason is recorded on the answer's `error`. Our outage should not become yours, so a network failure, an exhausted quota or a rejected key all fail open. Pass `fail_closed=True` to block instead. Private addresses are answered locally and never fail, so this will not lock you out in development.

## Cost and latency

Answers are cached for an hour, so a returning visitor costs nothing, and private addresses never leave the process. A cache miss is one request to our API, bounded at 2.5 seconds by default and not retried: on a request path, failing open fast beats holding a visitor while we retry. Both are adjustable, as is the cache, through a `vpndetection` client you build yourself and pass as `client`.

Skip what you do not care about, or must never refuse:

```python
skip = lambda request: request.path.startswith("/webhooks/")
```

A webhook comes from its sender's servers, an address a hosting rule would refuse. Static files need no skip: `runserver`, WhiteNoise and a web server in front each answer them before this middleware runs.

Beyond a few million distinct visitors a day, stop calling the API per request: [download the dataset](https://vpndetection.io/#databases) and look addresses up locally instead.

## Absent is not false

Unlimited, with a key or without one, leaves out `is_hosting`, `is_cdn`, the four proxy flags, the carrier, satellite and service flags, `company` and `abuse`, and of the detail behind each flag it answers only Tor's and relay's. A field your plan does not include is `None`, which means "not in your plan" rather than "checked, and no".

```python
request.vpndetection.result.is_hosting  # None when your plan does not include it
```

A `block_condition` naming a member your plan does not serve can never match, so the middleware warns once instead of failing silently. Pass `on_missing_field="raise"` to make it an error.

## Other Libraries

There are official VPNDetection client libraries available for many languages including PHP, Python, Go, Java, Ruby, and many popular frameworks such as Django, Rails, and Laravel. See our GitHub at https://github.com/vpndetection-io for more.

## About VPNDetection

VPN Detection API: Accurate anonymity detection identifying VPNs, residential proxies, hosting servers, Tor nodes, CDNs, relays and more.

[<img src="https://s3.vpndetection.io/vpndetection-public/brand/mark.svg" alt="VPNDetection" height="64"/>](https://vpndetection.io/)

## License

This project is licensed under the [MIT License](LICENSE).
