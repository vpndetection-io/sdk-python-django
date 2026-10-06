# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 2.0.5 are described by their release commits.

## 2.2.2 - 2026-10-06

### Features

- Require vpndetection 5.7.0: the authorization code sign-in ([`9dd34fa`](https://github.com/vpndetection-io/sdk-python-django/commit/9dd34fa6d00c0af12534919009b288749020cd61))

## 2.2.1 - 2026-10-04

### Fixes

- Require vpndetection 5.6.1, re-pinned to spec 2026.10.03 ([`5ba2493`](https://github.com/vpndetection-io/sdk-python-django/commit/5ba249386ebd7490784c2dc7938b7a8cc450e311))

## 2.2.0 - 2026-10-03

### Features

- Add block_if, a decorator refusing one view to a visitor matching a condition ([`fdd23ab`](https://github.com/vpndetection-io/sdk-python-django/commit/fdd23ab04c0cd0f6d78af8957bcfb4c8d4f41f3d))

## 2.1.0 - 2026-10-02

### Features

- Add lookup(request), None for a request skip claimed ([`da424f7`](https://github.com/vpndetection-io/sdk-python-django/commit/da424f78af4c64083e3092f286502bc2241ece61))

### Fixes

- Require vpndetection 5.5.3: a long Retry-After or timeout no longer raises OverflowError ([`8bdd4bb`](https://github.com/vpndetection-io/sdk-python-django/commit/8bdd4bb937626e7727619d1829f422b85a176c4d))

## 2.0.8 - 2026-09-29

### Fixes

- Require vpndetection 5.5.2: 26 more reserved ranges are answered locally ([`74e8270`](https://github.com/vpndetection-io/sdk-python-django/commit/74e8270986bc5f354c972df6392c06f08f261889))

## 2.0.7 - 2026-09-28

### Fixes

- Require vpndetection 5.5.1: IPv4-mapped visitors are looked up, not waved through ([`7ca152d`](https://github.com/vpndetection-io/sdk-python-django/commit/7ca152d0008ebe8ba5ea7f55eb5c288df33d1de2))

## 2.0.6 - 2026-09-27

### Features

- Require vpndetection 5.5.0: OauthMetadata carries client_id_metadata_document_supported ([`521506a`](https://github.com/vpndetection-io/sdk-python-django/commit/521506a2ad42ef3ae86ab0150526dab9d0a23f0c))

## 2.0.5 - 2026-09-25

### Fixes

- Raise the base floor to vpndetection 5.4.2 ([`945c426`](https://github.com/vpndetection-io/sdk-python-django/commit/945c426b8d58bb41f66527fd6daa7e52b079258a))
