# Changelog

What each release changed for you, newest first. Each line is a commit's summary, linked to its full description and diff. Releases before 2.0.5 are described by their release commits.

## 2.2.13 - 2026-10-26

### Fixes

- Require vpndetection 5.12.2: re-pinned to the 2026.10.25 spec ([`755cd6b`](https://github.com/vpndetection-io/sdk-python-django/commit/755cd6bc9410afa4f62405caab32bee16d98e7af))

## 2.2.12 - 2026-10-25

### Fixes

- Require vpndetection 5.12.1: retry counts and dates are checked ([`28672bd`](https://github.com/vpndetection-io/sdk-python-django/commit/28672bd04b9794a7151b102fb281d9940c252c2b))

## 2.2.11 - 2026-10-23

### Fixes

- Require vpndetection 5.12.0, which adds oauth.register ([`612613b`](https://github.com/vpndetection-io/sdk-python-django/commit/612613b6e77a482a9b76d6f89a84868142abe242))

## 2.2.10 - 2026-10-22

### Fixes

- Require vpndetection 5.11.1: a wrong-typed member is a server_error ([`94cd965`](https://github.com/vpndetection-io/sdk-python-django/commit/94cd96553677577a9c0edeec0b58ff9858c4f8f8))

## 2.2.9 - 2026-10-20

### Features

- Require vpndetection 5.11.0: lookup results carry location and asn ([`45e343e`](https://github.com/vpndetection-io/sdk-python-django/commit/45e343e625d347b77a5f94bfc9c03f907e0283f3))

## 2.2.8 - 2026-10-19

### Fixes

- Require vpndetection 5.10.0: num_ports and num_proxies in the pubproxy detail ([`a09ecec`](https://github.com/vpndetection-io/sdk-python-django/commit/a09ececc5f9cec37d07e804480dac0f6c62b010b))

## 2.2.7 - 2026-10-18

### Fixes

- Require vpndetection 5.9.0: is_pubproxy and the pubproxy detail ([`0f6960c`](https://github.com/vpndetection-io/sdk-python-django/commit/0f6960cf2db6d45dd92743bc8d17c7c9c4d801ce))

## 2.2.6 - 2026-10-17

### Features

- Require vpndetection 5.8.0: OauthMetadata carries registration_endpoint ([`599c016`](https://github.com/vpndetection-io/sdk-python-django/commit/599c016879298a444bb80233840ddf1a8d0916de))

## 2.2.5 - 2026-10-16

### Fixes

- Require vpndetection 5.7.3: the spec re-pinned to 2026.10.15 ([`f51ca46`](https://github.com/vpndetection-io/sdk-python-django/commit/f51ca46c8446d862d764581c10675cc3755361bf))

## 2.2.4 - 2026-10-15

### Fixes

- Require vpndetection 5.7.2: Retry-After, the key, the base URL and unreadable answers ([`d59871e`](https://github.com/vpndetection-io/sdk-python-django/commit/d59871ee469ea3c91cd5e9143a0dabd1e4f90e51))

## 2.2.3 - 2026-10-10

### Fixes

- Require vpndetection 5.7.1: the spec re-pinned to 2026.10.09 ([`e864b26`](https://github.com/vpndetection-io/sdk-python-django/commit/e864b26b4ccd4424c3a26e0113d052faf296586b))

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
