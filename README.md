# aiovodafone

<p align="center">
  <a href="https://github.com/chemelli74/aiovodafone/actions/workflows/ci.yml?query=branch%3Amain">
    <img src="https://img.shields.io/github/actions/workflow/status/chemelli74/aiovodafone/ci.yml?branch=main&label=CI&logo=github&style=flat-square" alt="CI Status" >
  </a>
  <a href="https://codecov.io/gh/chemelli74/aiovodafone">
    <img src="https://img.shields.io/codecov/c/github/chemelli74/aiovodafone.svg?logo=codecov&logoColor=fff&style=flat-square" alt="Test coverage percentage">
  </a>
</p>
<p align="center">
  <a href="https://docs.astral.sh/uv/">
    <img src="https://img.shields.io/badge/packaging-uv-2A5BFF?style=flat-square" alt="uv">
  </a>
  <a href="https://github.com/ambv/black">
    <img src="https://img.shields.io/badge/code%20style-black-000000.svg?style=flat-square" alt="black">
  </a>
  <a href="https://pypi.org/project/prek/">
    <img src="https://img.shields.io/badge/prek-enabled-brightgreen?style=flat-square" alt="prek">
  </a>
</p>
<p align="center">
  <a href="https://pypi.org/project/aiovodafone/">
    <img src="https://img.shields.io/pypi/v/aiovodafone.svg?logo=python&logoColor=fff&style=flat-square" alt="PyPI Version">
  </a>
  <a href="https://pypi.org/project/aiovodafone/">
    <img src="https://img.shields.io/pypi/pyversions/aiovodafone.svg?style=flat-square&amp;logo=python&amp;logoColor=fff" alt="Supported Python versions">
  </a>
  <img src="https://img.shields.io/pypi/l/aiovodafone.svg?style=flat-square" alt="License">
</p>

---

**Source Code**: <a href="https://github.com/chemelli74/aiovodafone" target="_blank">https://github.com/chemelli74/aiovodafone </a>

---

Python library to control Vodafone Station

## Installation

Install this via pip (or your favourite package manager):

`pip install aiovodafone`

## Test

Test the library with:

`python library_test.py`

The script accept command line arguments or a library_test.json config file:

```json
{
  "router": "192.168.1.1",
  "username": "<your_username>",
  "password": "<your_password>"
}
```

## Contributors ✨

Thanks goes to these wonderful people ([emoji key](https://allcontributors.org/docs/en/emoji-key)):

<!-- prettier-ignore-start -->
<!-- readme: contributors -start -->
<table>
	<tbody>
		<tr>
            <td align="center">
                <a href="https://github.com/chemelli74">
                    <img src="https://avatars.githubusercontent.com/u/57354320?v=4" width="100;" alt="chemelli74"/>
                    <br />
                    <sub><b>Simone Chemelli</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/guerda">
                    <img src="https://avatars.githubusercontent.com/u/230782?v=4" width="100;" alt="guerda"/>
                    <br />
                    <sub><b>Philip Gillißen</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/sven-ruess">
                    <img src="https://avatars.githubusercontent.com/u/27511750?v=4" width="100;" alt="sven-ruess"/>
                    <br />
                    <sub><b>Sven Rueß</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/bdraco">
                    <img src="https://avatars.githubusercontent.com/u/663432?v=4" width="100;" alt="bdraco"/>
                    <br />
                    <sub><b>J. Nick Koston</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/pschmitt">
                    <img src="https://avatars.githubusercontent.com/u/37886?v=4" width="100;" alt="pschmitt"/>
                    <br />
                    <sub><b>Philipp Schmitt</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/Cmd12345">
                    <img src="https://avatars.githubusercontent.com/u/135260576?v=4" width="100;" alt="Cmd12345"/>
                    <br />
                    <sub><b>Cmd12345</b></sub>
                </a>
            </td>
		</tr>
		<tr>
            <td align="center">
                <a href="https://github.com/joostlek">
                    <img src="https://avatars.githubusercontent.com/u/7083755?v=4" width="100;" alt="joostlek"/>
                    <br />
                    <sub><b>Joost Lekkerkerker</b></sub>
                </a>
            </td>
            <td align="center">
                <a href="https://github.com/myhomeiot">
                    <img src="https://avatars.githubusercontent.com/u/70070601?v=4" width="100;" alt="myhomeiot"/>
                    <br />
                    <sub><b>myhomeiot</b></sub>
                </a>
            </td>
		</tr>
	<tbody>
</table>
<!-- readme: contributors -end -->
<!-- prettier-ignore-end -->

This project follows the [all-contributors](https://github.com/all-contributors/all-contributors) specification. Contributions of any kind welcome!

## Credits

This package was created with
[Copier](https://copier.readthedocs.io/) and the
[browniebroke/pypackage-template](https://github.com/browniebroke/pypackage-template)
project template.
