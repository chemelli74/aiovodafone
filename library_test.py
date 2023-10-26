import argparse
import asyncio
import logging

from aiovodafone.api import (
    VodafoneStationCommonApi,
    VodafoneStationSercommApi,
    VodafoneStationTechnicolorApi,
)
from aiovodafone.exceptions import (
    AlreadyLogged,
    CannotConnect,
    GenericLoginError,
    ModelNotSupported,
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
        "--device-type",
        "-d",
        type=str,
        default="Sercomm",
        help="Set device type, either Sercomm or Technicolor",
    )

    arguments = parser.parse_args()

    return parser, arguments


async def main() -> None:
    """Run main."""
    parser, args = get_arguments()

    if not args.password:
        print("You have to specify a password")
        exit(1)

    print("-" * 20)
    api: VodafoneStationCommonApi
    if args.device_type == "Technicolor":
        api = VodafoneStationTechnicolorApi(args.router, args.username, args.password)
    else:
        api = VodafoneStationSercommApi(args.router, args.username, args.password)

    exc = True
    try:
        await api.login()
        exc = False
    except ModelNotSupported:
        print("Model is not supported yet for router", api.host)
    except CannotConnect:
        print("Cannot connect to router", api.host)
    except AlreadyLogged:
        print("Only one user at a time can connect to router", api.host)
    except GenericLoginError:
        print("Unable to login to router", api.host)
    finally:
        if exc:
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
