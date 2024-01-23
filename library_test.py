import argparse
import asyncio
import json
import logging
import os

import aiohttp

from aiovodafone.api import (
    VodafoneStationArrisApi,
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


def get_arguments() -> tuple[argparse.ArgumentParser, argparse.Namespace]:
    """Get parsed passed in arguments."""
    parser = argparse.ArgumentParser(description="aiovodafone library test")
    parser.add_argument(
        "--router", "-r", type=str, default="192.168.1.1", help="Set router IP address"
    )
    parser.add_argument(
        "--username", "-u", type=str, default="vodafone", help="Set router username"
    )
    parser.add_argument("--password", "-p", type=str, help="Set router password")
    parser.add_argument(
        "--configfile",
        "-cf",
        type=str,
        help="Load options from JSON config file. Command line options override those in the file.",
    )

    arguments = parser.parse_args()
    if arguments.configfile:
        # Re-parse the command line, taking the options in the optional JSON file as a basis
        if os.path.exists(arguments.configfile):
            with open(arguments.configfile) as f:
                arguments = parser.parse_args(
                    namespace=argparse.Namespace(**json.load(f))
                )

    return parser, arguments


async def main() -> None:
    """Run main."""
    parser, args = get_arguments()

    if not args.password:
        print("You have to specify a password")
        parser.print_help()
        exit(1)

    print("Determining device type")
    async with aiohttp.ClientSession() as session:
        device_type = await VodafoneStationCommonApi.get_device_type(
            args.router, session
        )
        print(device_type)

    print("-" * 20)
    api: VodafoneStationCommonApi
    if device_type == DeviceType.TECHNICOLOR:
        api = VodafoneStationTechnicolorApi(args.router, args.username, args.password)
    elif device_type == DeviceType.ARRIS:
        api = VodafoneStationArrisApi(args.router, args.username, args.password)
    elif device_type == DeviceType.SERCOMM:
        api = VodafoneStationSercommApi(args.router, args.username, args.password)
    else:
        print("The device is not a supported Vodafone Station.")
        exit(1)

    try:
        try:
            await api.login()
        except ModelNotSupported:
            print("Model is not supported yet for router", api.host)
            raise
        except CannotAuthenticate:
            print("Cannot authenticate to router", api.host)
            raise
        except CannotConnect:
            print("Cannot connect to router", api.host)
            raise
        except AlreadyLogged:
            print("Only one user at a time can connect to router", api.host)
            raise
        except GenericLoginError:
            print("Unable to login to router", api.host)
            raise
    except VodafoneError:
        await api.close()
        exit(1)

    print("Logged-in.")

    print("-" * 20)
    devices = await api.get_devices_data()
    print("Devices:", devices)
    print("-" * 20)
    data = await api.get_sensor_data()
    print("Data:", data)
    print("-" * 20)
    print("Serial #:", data["sys_serial_number"])
    print("Firmware:", data["sys_firmware_version"])
    print("Hardware:", data["sys_hardware_version"])
    print("Uptime  :", api.convert_uptime(data["sys_uptime"]))
    print("-" * 20)
    print("Logout & close session")
    await api.logout()
    await api.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("charset_normalizer").setLevel(logging.INFO)
    asyncio.run(main())
