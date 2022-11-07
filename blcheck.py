"""Module providing regex function and printing."""
import re
import sys

__title__ = "Blacklists Checker"
__filename__ = "blcheck.py"
__description__ = "It verify if a domain name or an IP is on a blacklist."
__version__ = "1.0.4"
__status__ = "Production"
__python_version__ = "3"
__author__ = "y-n0t"
__license__ = "GPL"


try:
    import dns.resolver
except ModuleNotFoundError as e:
    MSG = """The module dns was not found!
    On linux, you can install it with: apt-get install python3-dnspython.
    With PIP: python3 -m pip install dnspython"""
    raise SystemExit(MSG) from e


# DNSBL list
dnsblList = (
    "all.s5h.net",
    "b.barracudacentral.org",
    "bl.spamcop.net",
    "cbl.abuseat.org",
    "db.wpbl.info",
    "dnsbl-1.uceprotect.net",
    "dnsbl-2.uceprotect.net",
    "dnsbl-3.uceprotect.net",
    "dnsbl.anticaptcha.net",
    "dnsbl.dronebl.org",
    "dnsbl.inps.de",
    "dnsbl.sorbs.net",
    "dnsbl.spfbl.net",
    "drone.abuse.ch",
    "duinv.aupads.org",
    "dul.dnsbl.sorbs.net",
    "dyna.spamrats.com",
    "dynip.rothen.com",
    "http.dnsbl.sorbs.net",
    "ips.backscatterer.org",
    "ix.dnsbl.manitu.net",
    "korea.services.net",
    "misc.dnsbl.sorbs.net",
    "noptr.spamrats.com",
    "orvedb.aupads.org",
    "pbl.spamhaus.org",
    "proxy.bl.gweep.ca",
    "psbl.surriel.com",
    "relays.bl.gweep.ca",
    "relays.nether.net",
    "sbl.spamhaus.org",
    "smtp.dnsbl.sorbs.net",
    "socks.dnsbl.sorbs.net",
    "spam.dnsbl.sorbs.net",
    "spam.spamrats.com",
    "spambot.bls.digibase.ca",
    "ubl.lashback.com",
    "ubl.unsubscore.com",
    "web.dnsbl.sorbs.net",
    "wormrbl.imp.ch",
    "xbl.spamhaus.org",
    "z.mailspike.net",
    "zen.spamhaus.org",
    "zombie.dnsbl.sorbs.net",
)


def version() -> None:
    """Show some information about the soft"""
    version_message = f"""\n{__title__}    v{__version__}

{__description__}
Number of DNSBL in the list: {len(dnsblList)}
Author: {__author__}
License: {__license__}
Release: {__status__}\n"""

    print(version_message)


def helpme() -> None:
    """Show some examples"""
    help_msg = f"""\n{__title__}    v{__version__}

{__description__}
Number of DNSBL in the list: {len(dnsblList)}

Example: python blcheck.py mail.example.com
         python blcheck.py 8.8.8.8\n"""

    print(help_msg)


def validate_ip(p_ip: str) -> bool:
    """Verify that the IP address is a valid format.

    Args:
        p_ip (str): An IP address.

    Returns:
        bool: True if the IP is valid.
    """
    # Regular expression for validating an IP address
    valid_ip_address_regex = r"^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$"

    return bool(re.search(valid_ip_address_regex, p_ip))


def validate_hostname(p_host: str) -> bool:
    """Verify that the hostname is a valid format.

    Args:
        p_host (str): A hostname.

    Returns:
        bool: True if it is valid.
    """
    # Regular expression for validating a hostname
    valid_hostname_regex = r"^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z])$"

    return bool(re.search(valid_hostname_regex, p_host))


def reverse_ip(p_ip: str) -> str:
    """Reverse the IP to the addr format.

    Args:
        p_ip (str): An IP address.

    Returns:
        str: The IP in reversed.
    """
    temp_list = p_ip.split(".")
    return temp_list[3] + "." + temp_list[2] + "." + temp_list[1] + "." + temp_list[0]


def rbl_dns_query(p_host: str) -> bool:
    """Check if the provided IP is on an DNSBL list (blacklist) and print the output on STDOUT.

    Args:
        p_host (str): A hostname.

    Returns:
        bool: True if the IP is found a the blacklist.
    """
    try:
        if myResolver.query(p_host, "A"):
            return True
        return False

    except dns.resolver.Timeout:
        print("Timeout No answers could be found in the specified lifetime.")
    except dns.resolver.NXDOMAIN:
        print("NXDOMAIN The query name does not exist.")
    except dns.resolver.YXDOMAIN:
        print("YXDOMAIN The query name is too long after DNAME substitution.")
    except dns.resolver.NoAnswer:
        print(
            "NoAnswer The response did not contain an answer and raise_on_no_answer is True."
        )
    except dns.resolver.NoNameservers:
        print(
            "NoNameservers No non-broken nameservers are available to answer the question."
        )
    except Exception as error:
        print(error)


def check_spam_list(p_ip: str) -> None:
    """Loop on the DNSBL list (blacklist) declared above and print the output on STDOUT.

    Args:
        p_ip (str): An IP address.
    """
    total_found = 0
    i = 1
    print(f"IP to analyse: {p_ip}\n")
    host_to_check = reverse_ip(p_ip)
    for dnsbl in dnsblList:
        print(f"{i} : {dnsbl} : ", end="")
        try:
            if rbl_dns_query(host_to_check + "." + dnsbl):
                print("BAD! This IP is listed here.")
                total_found += 1
        except Exception:
            pass
        i += 1

    print(f"\nTotal found = {total_found}/{len(dnsblList)}\n")

    if total_found > 0:
        raise SystemExit(
            f"This is BAD, this IP was found {total_found} times.\n")

    print("This is GOOD, this IP was not found at all.\n")


def get_ip(p_host: str) -> str:
    """Return IP address of host.

    Args:
        p_host (str): The hostname to get its IP.

    Returns:
        str: host IP, if found.
    """
    try:
        query_result = myResolver.query(p_host, "A")
        for result in query_result:
            return str(result)

    except dns.resolver.Timeout as timeout:
        raise SystemExit(
            "Timeout No answers could be found in the specified lifetime."
        ) from timeout
    except dns.resolver.NXDOMAIN as nxdomain:
        raise SystemExit(
            "NXDOMAIN The query name does not exist.") from nxdomain
    except dns.resolver.YXDOMAIN as yxdomain:
        raise SystemExit(
            "YXDOMAIN The query name is too long after DNAME substitution."
        ) from yxdomain
    except dns.resolver.NoAnswer as noanswer:
        raise SystemExit(
            "NoAnswer The response did not contain an answer and raise_on_no_answer is True."
        ) from noanswer
    except dns.resolver.NoNameservers as nonameservers:
        raise SystemExit(
            "NoNameservers No non-broken nameservers are available to answer the question."
        ) from nonameservers
    except Exception as else_error:
        raise SystemExit(else_error) from else_error


if __name__ == "__main__":
    # First thing first, check if an argument exist, if not exit.
    if len(sys.argv) == 1:
        raise SystemExit(
            "Error: no argument: it requires an IP or a hostname.")

    # Define the argument as arg1
    arg1: str = sys.argv[1]

    if arg1 in ("--version", "-v"):
        version()
        sys.exit(0)

    if arg1 in ("--help", "-h"):
        helpme()
        sys.exit(0)

    # Show stuff at the console
    print(f"\n{__title__}    v{__version__}\n")
    print(f"Number of DNSBL in the list: {len(dnsblList)}\n\n")

    # Settings for the dns.resolver module
    myResolver = dns.resolver.Resolver()

    # If True (the default), the resolver instance is configured in the normal fashion for the operating system the
    # resolver is running on. (I.e. a /etc/resolv.conf file on POSIX systems and from the registry on Windows systems.)
    # So here, we turned this off.
    myResolver.default_resolver = dns.resolver.Resolver(configure=False)

    # Define your DNS resolvers here, or use Google's.
    myResolver.default_resolver.nameservers = ["8.8.8.8", "8.8.4.4"]

    # The number of seconds to wait for a response from a server, before timing out.
    myResolver.timeout = 3

    # The total number of seconds to spend trying to get an answer to the question.
    myResolver.lifetime = 3

    try:
        # Check if the IP is valid, if applicable.
        IS_VALID_IP = validate_ip(arg1)

        # If it is an IP, do you stuff and quit...
        if IS_VALID_IP:
            check_spam_list(arg1)
            sys.exit(0)

        # Check if the provided name is a valid hostname.
        IS_VALID_HOSTNAME = validate_hostname(arg1)

        # If the hostname is valid and it was not an IP, do you stuff...
        if IS_VALID_HOSTNAME and not IS_VALID_IP:
            print("Getting the IP for:", arg1)

            # DNS query to get the IP of the provided hostname.
            ip: str = get_ip(arg1)

            # If an IP was found.
            if ip:
                check_spam_list(ip)
                sys.exit(0)
            else:
                raise SystemExit(
                    f"Error: an IP has not been found for: {arg1}")

        if not IS_VALID_HOSTNAME and not IS_VALID_IP:
            raise SystemExit(
                f"Error: This argument is not a valid IP or hostname: {arg1}"
            )

    except Exception as e:
        print(e)
