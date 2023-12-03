# Changelog

<!--next-version-placeholder-->

## v0.5.0 (2023-12-03)

### Feature

* Add specific check for sercom CSRF token ([`a8f1780`](https://github.com/chemelli74/aiovodafone/commit/a8f178012ec5e1679cdb44ba080cee64ad27fa23))
* Device detection, consider None as result ([`bb5204a`](https://github.com/chemelli74/aiovodafone/commit/bb5204ab1808b40b268f0c75c272a96c5f31281d))
* Require aiohttp.ClientSession to determine device type ([`cdb4637`](https://github.com/chemelli74/aiovodafone/commit/cdb46375d3c04b50dfb01c18ab82f1dc70607048))
* Add additional detection for Sercomm devices ([`6a3f4c0`](https://github.com/chemelli74/aiovodafone/commit/6a3f4c03af738705c8181a0126bf891527bd66fa))
* Add method to determine a device type ([`eb4f9c5`](https://github.com/chemelli74/aiovodafone/commit/eb4f9c50f1bd78c8b05fbadcf7bf0cc6b5ea529b))

### Documentation

* Explain why code lookup is needed for Sercomm devices ([`b137975`](https://github.com/chemelli74/aiovodafone/commit/b137975610697db46094f19c465b7f8ec07aa7fd))

## v0.4.3 (2023-11-28)

### Fix

* Recreate closed aiohttp session ([`a2ec07b`](https://github.com/chemelli74/aiovodafone/commit/a2ec07b150118a64323e82a0d17b079603b73a03))

## v0.4.2 (2023-10-26)

### Fix

* Improve failed login handling ([`c39ffd1`](https://github.com/chemelli74/aiovodafone/commit/c39ffd1439dd7d5008945fcb5946e96402429239))

## v0.4.1 (2023-10-17)

### Fix

* Add timezone to convert_uptime functions ([`d37cdbd`](https://github.com/chemelli74/aiovodafone/commit/d37cdbdca87955d4e0872aad69dd7f98351bcf91))

## v0.4.0 (2023-10-16)

### Feature

* Add device type for Technicolor devices ([`2133eb4`](https://github.com/chemelli74/aiovodafone/commit/2133eb45639f426e12ba61b8f80f9ba0b6424c74))
* Use generic post and get methods for Technicolor ([`170043f`](https://github.com/chemelli74/aiovodafone/commit/170043f38fffacacfccb2001efa04bfdb53e4752))
* Support Technicolor Vodafone Stations from Germany ([`09989a6`](https://github.com/chemelli74/aiovodafone/commit/09989a6b83c12347fc1826a5d59da68f2a9f77b7))

### Fix

* Add abstract method for convert_uptime ([`9a2bc9d`](https://github.com/chemelli74/aiovodafone/commit/9a2bc9d2105e39bf390f2101bafdb7a758e4498e))

## v0.3.2 (2023-10-12)

### Fix

* Timestamp formatting works on Windows ([`e614eac`](https://github.com/chemelli74/aiovodafone/commit/e614eacc0f93c638cea64ed0a685d610bd34f14f))

## v0.3.1 (2023-09-26)

### Fix

* Make BeautifulSoup parsing more robust ([`dc2d47b`](https://github.com/chemelli74/aiovodafone/commit/dc2d47b9aafcb8ada255b05640ae59f1b5cbc98b))

## v0.3.0 (2023-09-20)

### Feature

* Connection_type() ([`f0d82a3`](https://github.com/chemelli74/aiovodafone/commit/f0d82a33ca8824bcbb0deb02a1f2c0f13d7f13a3))

## v0.2.1 (2023-09-19)

### Fix

* Mypy new version's complains ([`b8a552d`](https://github.com/chemelli74/aiovodafone/commit/b8a552d4015995135f1c80faa21fee388985b82e))

## v0.2.0 (2023-09-10)

### Feature

* Basic checks to verify if model is supported ([`c3c34ff`](https://github.com/chemelli74/aiovodafone/commit/c3c34ff442008ec009299b882906041c51b3ef14))

### Fix

* Missing wifi band info on some models ([`304c254`](https://github.com/chemelli74/aiovodafone/commit/304c254e7c3895bbc7b636c0a56523fbef4cc3ea))

## v0.1.0 (2023-09-07)

### Feature

* Full sensor data, restart connection/router ([`db68478`](https://github.com/chemelli74/aiovodafone/commit/db684781d2b732f7920209cf0ef6f0c4af2e6ec5))
* Full sensor data, restart connection/router ([`3f40512`](https://github.com/chemelli74/aiovodafone/commit/3f40512e5170bb3e1173ceafa6d7d44ee02a45eb))

### Fix

* Handle credentials with special characters ([`d3b0a14`](https://github.com/chemelli74/aiovodafone/commit/d3b0a14910908735c5c87615ba51c8e227581c59))
* Handle credentials with special characters ([`1b4a6cd`](https://github.com/chemelli74/aiovodafone/commit/1b4a6cd5af2c6c644b2077515ad3164faab30c64))

## v0.0.8 (2023-09-05)

### Fix

* Labels ([`6c78985`](https://github.com/chemelli74/aiovodafone/commit/6c7898585ee8ab9b8945e8bf1c86dcb5dca7cf7f))
* Labels ([`2e24074`](https://github.com/chemelli74/aiovodafone/commit/2e240749b1c41b7c3a025947191b68d92b7438a4))

## v0.0.7 (2023-09-05)

### Fix

* Legacy device login ([`6dbb329`](https://github.com/chemelli74/aiovodafone/commit/6dbb3299d849a19d107624d6759fae8283594dbd))
* Legacy device login ([`8b10e98`](https://github.com/chemelli74/aiovodafone/commit/8b10e98170d6c99929a25fed1ca43b504a51dc81))

## v0.0.6 (2023-08-22)

### Fix

* Poetry lock ([`b489804`](https://github.com/chemelli74/aiovodafone/commit/b4898044c77a6172cc28796f57832951cf2281f2))

## v0.0.5 (2023-07-28)

### Fix

* Improve login handling ([`e50cf1a`](https://github.com/chemelli74/aiovodafone/commit/e50cf1a8ebf47b2088d9e43d321b6b18329d97bb))
* Stop script if login fails ([`3a31c02`](https://github.com/chemelli74/aiovodafone/commit/3a31c025660443c3455f5d3e2acab4721c34a0be))
* Drop python 3.9 ([`dd2ecb6`](https://github.com/chemelli74/aiovodafone/commit/dd2ecb66a9d5be687c4c576ae3e806f24791d6a5))

## v0.0.4 (2023-07-01)

### Fix

* Adjust permissions to allow release ([`c8667b4`](https://github.com/chemelli74/aiovodafone/commit/c8667b463f339b7001ee4e6314610065ac9b9c6d))
* Remove legacy python versions that do not support old typing ([#2](https://github.com/chemelli74/aiovodafone/issues/2)) ([`c6d6a87`](https://github.com/chemelli74/aiovodafone/commit/c6d6a8789a723487c65c4bc84ed71d250a987821))
* Add some basic sanity tests ([#1](https://github.com/chemelli74/aiovodafone/issues/1)) ([`1d813d3`](https://github.com/chemelli74/aiovodafone/commit/1d813d3aa798221ceb982ae6b32bb3b5c942422a))
* Dependencies fix ([`118e1b3`](https://github.com/chemelli74/aiovodafone/commit/118e1b335b2cb9132295ba8e59cc84d77caef4ee))
