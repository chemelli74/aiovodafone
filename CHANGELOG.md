# Changelog


### Documentation

- Contrib-readme-action has updated readme ([`d50e5dd`](https://github.com/Cmd12345/aiovodafone/commit/d50e5dd2a50832c585eba8a99a88c642588d1866))
- Pylance clienttimeout ([`d263242`](https://github.com/Cmd12345/aiovodafone/commit/d2632420c8e97aabd283aaf48580795022d97d40))
- Explain why code lookup is needed for sercomm devices ([`b137975`](https://github.com/Cmd12345/aiovodafone/commit/b137975610697db46094f19c465b7f8ec07aa7fd))


### Refactoring

- Improve dev container settings ([`a1c016b`](https://github.com/Cmd12345/aiovodafone/commit/a1c016bdeb0be0dbd953049d8bd48e99bd9e556f))
- Update pyproject.toml ([`6fb8e12`](https://github.com/Cmd12345/aiovodafone/commit/6fb8e122601eb7e71e9009843ffc5eebd225f2f2))
- Improve typing ([`12eb8ad`](https://github.com/Cmd12345/aiovodafone/commit/12eb8ad53c755d758e4c23c824831749d39165b2))
- Unify post and get internal requests ([`b8566c0`](https://github.com/Cmd12345/aiovodafone/commit/b8566c016213c3f7dc2a313d846f67c1eddf59f6))
- Fix typing ([`beca105`](https://github.com/Cmd12345/aiovodafone/commit/beca1056180db2d2c4fcd7b3db249fffc016193b))
- Use clienttimeout - part 2 ([`4d3f161`](https://github.com/Cmd12345/aiovodafone/commit/4d3f16118121818b1b5d744e1db8998e5ecbe144))
- Use clienttimeout ([`dd2ff01`](https://github.com/Cmd12345/aiovodafone/commit/dd2ff010dce093a80eae45166323069653cefe1b))
- Short parameter for config file -cf instead of -f ([`c354354`](https://github.com/Cmd12345/aiovodafone/commit/c354354e41825ca2e66eac7accbb5bbe31fa4e2c))
- Make library_test.py accept json config file ([`79956dd`](https://github.com/Cmd12345/aiovodafone/commit/79956dd93ce4d0778573abf19a280f8760e9cabb))
- Remove device type argument ([`36978a1`](https://github.com/Cmd12345/aiovodafone/commit/36978a14754aeae65e4f99ceb3490e5500dd1f2c))
- Add staticmethod decorator, line breaks ([`92cb428`](https://github.com/Cmd12345/aiovodafone/commit/92cb4284825a1c4fb64941856bb246e9e81d6f81))
- Update library_test ([`f2abc82`](https://github.com/Cmd12345/aiovodafone/commit/f2abc82812ca007a83d1e6576f065b7733dc166e))
- Inline page urls and extract login message ([`d53faa9`](https://github.com/Cmd12345/aiovodafone/commit/d53faa94c698cb2e771044218a7dd2d318e6d9db))
- Use one set of header for all types of stations ([`18c2633`](https://github.com/Cmd12345/aiovodafone/commit/18c2633f25328cfcb440125cb37479bf7a35db02))
- Make get and post more generic ([`f91daf0`](https://github.com/Cmd12345/aiovodafone/commit/f91daf0a56beae2a15fcb336e4a656ca56e75604))
- Move close to common api ([`a779243`](https://github.com/Cmd12345/aiovodafone/commit/a779243cacf00eb362ce30cc0552cedf213f9641))
- Add technicolor firmware api structure ([`7c52386`](https://github.com/Cmd12345/aiovodafone/commit/7c52386e8e15acc1b85ad66d5251fecb64cbfe68))
- Logout/close ([`8d053c3`](https://github.com/Cmd12345/aiovodafone/commit/8d053c329dbb349728bcd642803d3bd446551b16))


### Testing

- Align code to aiohttp >= 3.12.7 ([`e44a064`](https://github.com/Cmd12345/aiovodafone/commit/e44a064d4d82c88a74502d6e3a22314ba6f1bfe6))
- Cleanup .coveragerc ([`48d08fa`](https://github.com/Cmd12345/aiovodafone/commit/48d08fa726bef4b2e8a1921f6b04383c8c9f2c12))


### Features

- Add ping, dns and traceroute for technicolor devices ([`8d2720d`](https://github.com/Cmd12345/aiovodafone/commit/8d2720de7e0caad35749d9406dee6ad656b984e4))
- Technicolor router restart ([`3400810`](https://github.com/Cmd12345/aiovodafone/commit/3400810c253d09e231be8292354daf44dc795141))
- Pass clientsession(aiohttp) as parameter ([`d33abb5`](https://github.com/Cmd12345/aiovodafone/commit/d33abb5f263cb82f3136beb6336537277dbc314f))
- Add force parameter ([`5d3ab4f`](https://github.com/Cmd12345/aiovodafone/commit/5d3ab4ff71de999f5fdca9c27ae9108b79a8b168))
- Added docis and voice information for technicolor modems ([`bf769ad`](https://github.com/Cmd12345/aiovodafone/commit/bf769adf1366f340d8516231ec93be3f8d0099b3))
- Drop python 3.11 support ([`b4b1fe7`](https://github.com/Cmd12345/aiovodafone/commit/b4b1fe7207defadbf5bcf5c0753542fdd45756a2))
- Drop python 3.11 support ([`b4b1fe7`](https://github.com/Cmd12345/aiovodafone/commit/b4b1fe7207defadbf5bcf5c0753542fdd45756a2))
- Support for vodafone sercomm h300s ([`4608915`](https://github.com/Cmd12345/aiovodafone/commit/46089158bdfb49c69770a08da2c9756b11619fb2))
- Add specific check for sercom csrf token ([`a8f1780`](https://github.com/Cmd12345/aiovodafone/commit/a8f178012ec5e1679cdb44ba080cee64ad27fa23))
- Device detection, consider none as result ([`bb5204a`](https://github.com/Cmd12345/aiovodafone/commit/bb5204ab1808b40b268f0c75c272a96c5f31281d))
- Require aiohttp.clientsession to determine device type ([`cdb4637`](https://github.com/Cmd12345/aiovodafone/commit/cdb46375d3c04b50dfb01c18ab82f1dc70607048))
- Add additional detection for sercomm devices ([`6a3f4c0`](https://github.com/Cmd12345/aiovodafone/commit/6a3f4c03af738705c8181a0126bf891527bd66fa))
- Add method to determine a device type ([`eb4f9c5`](https://github.com/Cmd12345/aiovodafone/commit/eb4f9c50f1bd78c8b05fbadcf7bf0cc6b5ea529b))
- Add device type for technicolor devices ([`2133eb4`](https://github.com/Cmd12345/aiovodafone/commit/2133eb45639f426e12ba61b8f80f9ba0b6424c74))
- Use generic post and get methods for technicolor ([`170043f`](https://github.com/Cmd12345/aiovodafone/commit/170043f38fffacacfccb2001efa04bfdb53e4752))
- Support technicolor vodafone stations from germany ([`09989a6`](https://github.com/Cmd12345/aiovodafone/commit/09989a6b83c12347fc1826a5d59da68f2a9f77b7))
- Connection_type() ([`f0d82a3`](https://github.com/Cmd12345/aiovodafone/commit/f0d82a33ca8824bcbb0deb02a1f2c0f13d7f13a3))
- Basic checks to verify if model is supported ([`c3c34ff`](https://github.com/Cmd12345/aiovodafone/commit/c3c34ff442008ec009299b882906041c51b3ef14))
- Full sensor data, restart connection/router ([`3f40512`](https://github.com/Cmd12345/aiovodafone/commit/3f40512e5170bb3e1173ceafa6d7d44ee02a45eb))


### Unknown

### Bug fixes

- Fixed missing voice data for output ([`9ff4707`](https://github.com/Cmd12345/aiovodafone/commit/9ff470705caa5692675ad94d76e70f8fb4c102bd))
- Optimize logging with ruff g004 ([`17cf4a2`](https://github.com/Cmd12345/aiovodafone/commit/17cf4a23f9a899ec8481107737fa4b311e89f0f0))
- Fix license classifier ([`4e15884`](https://github.com/Cmd12345/aiovodafone/commit/4e15884397fd9714c3d7599d74f289b51dfc1c2d))
- Fix license classifier ([`f929cfc`](https://github.com/Cmd12345/aiovodafone/commit/f929cfc8e62610953bd20780eafe9023a5e86647))
- Check logged-in before resatrt connection/router ([`ea994a9`](https://github.com/Cmd12345/aiovodafone/commit/ea994a9485312c3c1da13a75b2bd4023937e7629))
- Improve logging ([`782537e`](https://github.com/Cmd12345/aiovodafone/commit/782537e50d7aef9cc4e287f6e9bcc88fea2691f1))
- Various fixes for get_device_type ([`ec8f01f`](https://github.com/Cmd12345/aiovodafone/commit/ec8f01fc4be5ea22927b985f8148002b11419e85))
- Interpret connected state correctly ([`686e19a`](https://github.com/Cmd12345/aiovodafone/commit/686e19a70ce31cbec55f809eb48f6a2bceef5ff7))
- Recreate closed aiohttp session ([`a2ec07b`](https://github.com/Cmd12345/aiovodafone/commit/a2ec07b150118a64323e82a0d17b079603b73a03))
- Improve failed login handling ([`c39ffd1`](https://github.com/Cmd12345/aiovodafone/commit/c39ffd1439dd7d5008945fcb5946e96402429239))
- Add timezone to convert_uptime functions ([`d37cdbd`](https://github.com/Cmd12345/aiovodafone/commit/d37cdbdca87955d4e0872aad69dd7f98351bcf91))
- Add abstract method for convert_uptime ([`9a2bc9d`](https://github.com/Cmd12345/aiovodafone/commit/9a2bc9d2105e39bf390f2101bafdb7a758e4498e))
- Timestamp formatting works on windows ([`e614eac`](https://github.com/Cmd12345/aiovodafone/commit/e614eacc0f93c638cea64ed0a685d610bd34f14f))
- Make beautifulsoup parsing more robust ([`dc2d47b`](https://github.com/Cmd12345/aiovodafone/commit/dc2d47b9aafcb8ada255b05640ae59f1b5cbc98b))
- Mypy new version's complains ([`b8a552d`](https://github.com/Cmd12345/aiovodafone/commit/b8a552d4015995135f1c80faa21fee388985b82e))
- Missing wifi band info on some models ([`304c254`](https://github.com/Cmd12345/aiovodafone/commit/304c254e7c3895bbc7b636c0a56523fbef4cc3ea))
- Handle credentials with special characters ([`1b4a6cd`](https://github.com/Cmd12345/aiovodafone/commit/1b4a6cd5af2c6c644b2077515ad3164faab30c64))
- Labels ([`2e24074`](https://github.com/Cmd12345/aiovodafone/commit/2e240749b1c41b7c3a025947191b68d92b7438a4))
- Legacy device login ([`8b10e98`](https://github.com/Cmd12345/aiovodafone/commit/8b10e98170d6c99929a25fed1ca43b504a51dc81))
- Poetry lock ([`b489804`](https://github.com/Cmd12345/aiovodafone/commit/b4898044c77a6172cc28796f57832951cf2281f2))
- Stop script if login fails ([`3a31c02`](https://github.com/Cmd12345/aiovodafone/commit/3a31c025660443c3455f5d3e2acab4721c34a0be))
- Drop python 3.9 ([`dd2ecb6`](https://github.com/Cmd12345/aiovodafone/commit/dd2ecb66a9d5be687c4c576ae3e806f24791d6a5))
- Adjust permissions to allow release ([`c8667b4`](https://github.com/Cmd12345/aiovodafone/commit/c8667b463f339b7001ee4e6314610065ac9b9c6d))
- Remove legacy python versions that do not support old typing ([`c6d6a87`](https://github.com/Cmd12345/aiovodafone/commit/c6d6a8789a723487c65c4bc84ed71d250a987821))
- Add some basic sanity tests ([`1d813d3`](https://github.com/Cmd12345/aiovodafone/commit/1d813d3aa798221ceb982ae6b32bb3b5c942422a))
- Dependencies fix ([`118e1b3`](https://github.com/Cmd12345/aiovodafone/commit/118e1b335b2cb9132295ba8e59cc84d77caef4ee))


### Code style

- Reorderd methods in api to have same listing as definition order of abstract class ([`2438038`](https://github.com/Cmd12345/aiovodafone/commit/2438038b446b40fbc224bd13845a1d76a2b5b3a8))
