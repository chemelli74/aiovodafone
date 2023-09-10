import argparse
import asyncio
import logging

from aiovodafone.api import VodafoneStationApi
from aiovodafone.exceptions import AlreadyLogged, CannotConnect, ModelNotSupported


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

    arguments = parser.parse_args()

    return parser, arguments


async def main() -> None:
    """Run main."""
    parser, args = get_arguments()

    if not args.password:
        print("You have to specify a password")
        exit(1)

    print("-" * 20)
    api = VodafoneStationApi(args.router, args.username, args.password)
    logged = False
    exc = False
    try:
        logged = await api.login()
    except ModelNotSupported:
        print("Model is not supported yet for router", api.host)
        exc = True
    except CannotConnect:
        print("Cannot connect to router", api.host)
        exc = True
    except AlreadyLogged:
        print("Only one user at a time can connect to router", api.host)
        exc = True
    finally:
        if not logged:
            if not exc:
                print("Unable to login to router", api.host)
            await api.close()
            exit(1)
    print("Logged:", logged)

    print("-" * 20)
    devices = await api.get_devices_data()
    print("Devices:", devices)
    print("-" * 20)
    data = await api.get_sensor_data()
    print("Data:", data)
    print("-" * 20)
    print("Serial #  :", data["sys_serial_number"])
    print("Firmware  :", data["sys_firmware_version"])
    print("Hardware  :", data["sys_hardware_version"])
    print("Connection:", await api.connection_type())
    print("Uptime    :", await api.convert_uptime(data["sys_uptime"]))
    print("-" * 20)
    print("Logout & close session")
    await api.logout()
    await api.close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger("asyncio").setLevel(logging.INFO)
    logging.getLogger("charset_normalizer").setLevel(logging.INFO)
    asyncio.run(main())
