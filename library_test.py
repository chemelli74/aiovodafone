"""Test script for aiovodafone library."""

import asyncio
import json
import logging
import sys
from argparse import ArgumentParser, Namespace
from pathlib import Path

from aiohttp import ClientSession, CookieJar

from aiovodafone.api import (
    VodafoneStationCommonApi,
    VodafoneStationSercommApi,
    VodafoneStationTechnicolorApi,
)
from aiovodafone.const import DeviceType
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotAuthenticate,
    CannotConnect,
    GenericLoginError,
    ModelNotSupported,
    VodafoneError,
)


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
    parser.add_argument(
        "--username",
        "-u",
        type=str,
        default="vodafone",
        help="Set router username",
    )
    parser.add_argument("--password", "-p", type=str, help="Set router password")
    parser.add_argument(
        "--configfile",
        "-cf",
        type=str,
        help="Load options from JSON config file. \
        Command line options override those in the file.",
    )

    arguments = parser.parse_args()
    # Re-parse the command line
    # taking the options in the optional JSON file as a basis
    if arguments.configfile and Path(arguments.configfile).exists():
        with Path.open(arguments.configfile) as f:
            arguments = parser.parse_args(namespace=Namespace(**json.load(f)))

    return parser, arguments


async def logout_close_session(api: VodafoneStationCommonApi) -> None:
    """Logout and close aiohttp session."""
    print("-" * 20)
    print("Logout & close session")
    await api.logout()
    await api.close()


async def main() -> None:
    """Run main."""
    parser, args = get_arguments()

    if not args.password:
        print("You have to specify a password")
        parser.print_help()
        sys.exit(1)

    print("Creating HTTP ClientSession")
    jar = CookieJar(unsafe=True, quote_cookie=False)
    session = ClientSession(cookie_jar=jar)

    print("Determining device type")
    device_type = await VodafoneStationCommonApi.get_device_type(
        args.router,
        session,
    )
    print(device_type)

    print("-" * 20)
    api: VodafoneStationCommonApi
    if device_type == DeviceType.TECHNICOLOR:
        api = VodafoneStationTechnicolorApi(
            args.router,
            args.username,
            args.password,
            session,
        )
    elif device_type == DeviceType.SERCOMM:
        api = VodafoneStationSercommApi(
            args.router,
            args.username,
            args.password,
            session,
        )
    else:
        print("The device is not a supported Vodafone Station.")
        sys.exit(1)

    try:
        try:
            await api.login()
        except ModelNotSupported:
            print(f"Model is not supported yet for router {api.host}")
            raise
        except CannotAuthenticate:
            print(f"Cannot authenticate to router {api.host}")
            raise
        except CannotConnect:
            print(f"Cannot connect to router {api.host}")
            raise
        except AlreadyLogged:
            print(f"Only one user at a time can connect to router {api.host}")
            raise
        except GenericLoginError:
            print(f"Unable to login to router {api.host}")
            raise
    except VodafoneError:
        await api.close()
        sys.exit(1)

    print("Logged-in.")

    print("-" * 20)
    devices = await api.get_devices_data()
    print(f"Devices: {devices}")

    print("-" * 20)
    data = await api.get_sensor_data()
    print(f"Sensor data: {data}")
    print("-" * 20)
    print(f"{'Serial #:':>20} {data['sys_serial_number']}")
    print(f"{'Firmware:':>20} {data['sys_firmware_version']}")
    print(f"{'Hardware:':>20} {data['sys_hardware_version']}")
    print(f"{'Uptime:':>20} {api.convert_uptime(data['sys_uptime'])}")
    print(f"{'WAN status:':>20} {data.get('wan_status')}")
    print(f"{'Cable modem status:':>20} {data.get('cm_status')}")
    print(f"{'LAN mode:':>20} {data.get('lan_mode')}")

    # Sercomm devices don't support Docis data and Voice data
    if device_type == DeviceType.SERCOMM:
        await logout_close_session(api)
        return

    print("-" * 20)
    data = await api.get_docis_data()
    print(f"Docis data: {data}")
    print("-" * 20)
    for which in ["downstream", "upstream"]:
        print(f"{which}")
        for channel in data[which]:
            print(f"{channel}:")
            print(f"{'Type:':>15} {data[which][channel]['channel_type']}")
            print(f"{'Frequency:':>15} {data[which][channel]['channel_frequency']}")
            print(f"{'Modulation:':>15} {data[which][channel]['channel_modulation']}")
            print(f"{'Power:':>15} {data[which][channel]['channel_power']}")
            print(f"{'Locked:':>15} {data[which][channel]['channel_locked']}")

    print("-" * 20)
    data = await api.get_voice_data()
    print(f"Voice data: {data}")
    print("-" * 20)
    print(f"{'VoIP status:':>15} {data['general'].get('status', 'N/A')}")
    print(f"{'Line1:':>15} {data['line1'].get('status', 'N/A')}")
    print(f"{'Line1 number:':>15} {data['line1'].get('call_number', 'N/A')}")
    print(f"{'Line1 status:':>15} {data['line1'].get('line_status', 'N/A')}")
    print(f"{'Line2:':>15} {data['line2'].get('status', 'N/A')}")
    print(f"{'Line2 number:':>15} {data['line2'].get('call_number', 'N/A')}")
    print(f"{'Line2 status:':>15} {data['line2'].get('line_status', 'N/A')}")

    await logout_close_session(api)


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("charset_normalizer").setLevel(logging.INFO)
    asyncio.run(main())
