"""Collect html pages for Vodafone Station."""

import asyncio
import logging
from argparse import ArgumentParser, Namespace
from datetime import UTC, datetime
from pathlib import Path

import aiohttp


def get_arguments() -> tuple[ArgumentParser, Namespace]:
    """Get parsed passed in arguments."""
    parser = ArgumentParser(description="aiovodafone library test")
    parser.add_argument(
        "--router",
        "-r",
        type=str,
        default="192.168.1.1",
        help="Set router IP address",
    )
    arguments = parser.parse_args()

    return parser, arguments


async def main() -> None:
    """Run main."""
    _, args = get_arguments()

    print("-" * 20)

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (X11; Fedora; Linux x86_64; rv:78.0)"
            "Gecko/20100101 Firefox/78.0"
        ),
        "Accept": (
            "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8"
        ),
        "Accept-Language": "en-GB,en;q=0.5",
        "DNT": "1",
    }
    jar = aiohttp.CookieJar(unsafe=True)
    session = aiohttp.ClientSession(cookie_jar=jar)

    for protocol in ["http", "https"]:
        url = f"{protocol}://{args.router}/login.html"
        print("Saving", url)
        reply = await session.get(
            url,
            headers=headers,
            timeout=aiohttp.ClientTimeout(10),
            ssl=False,
            allow_redirects=True,
        )
        reply_text = await reply.text()

        with Path.open(
            Path(f"login-page-{protocol}-{datetime.now(tz=UTC)}.html"),
            "w+",
        ) as text_file:
            text_file.write(reply_text)
            text_file.close()
            print("-" * 20)

    await session.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("charset_normalizer").setLevel(logging.INFO)
    asyncio.run(main())
