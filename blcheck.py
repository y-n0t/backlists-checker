__title__ = "Blacklists Checker"
__filename__ = "blcheck.py"
__description__ = "Verify if a domain name or an IP is on a blacklist."
__version__ = "1.0.1"
__status__ = "Production"
__python_version__ = "3"
__author__ = "y-n0t"
__license__ = "GPL"

import re
import sys

try:
    import dns.resolver
except ModuleNotFoundError:
    raise SystemExit("The module dns was not found!\nOn linux, you can install it with: apt-get install python3-dnspython")


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
    "zombie.dnsbl.sorbs.net"
)


def version():
    """Show some information about the soft
    """
    print("\n{}    v{}\n".format(__title__, __version__))
    print("{}".format(__description__))
    print('Number of DNSBL in the list: %s' % len(dnsblList))
    print("Author: {}".format(__author__))
    print("License: {}".format(__license__))
    print("Release: {}".format(__status__))


def helpme():
    """Show some examples
    """
    print("\n{}    v{}\n".format(__title__, __version__))
    print("{}".format(__description__))
    print('Number of DNSBL in the list: %s' % len(dnsblList))
    print("\nExample: python blcheck.py mail.example.com")
    print("         python blcheck.py 8.8.8.8")


def validate_ip(p_ip):
    """Verify that the IP address is a valid format.

    Args:
        p_ip (str): An IP address.

    Returns:
        bool: True if the IP is valid.
    """
    # Regular expression for validating an IP address
    valid_ip_address_regex = '^(([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])\.){3}([0-9]|[1-9][0-9]|1[0-9]{2}|2[0-4][0-9]|25[0-5])$'

    if re.search(valid_ip_address_regex, p_ip):
        return True
    else:
        return False


def validate_hostname(p_host):
    """Verify that the hostname is a valid format.

    Args:
        p_host (str): A hostname.

    Returns:
        bool: True if it is valid.
    """
    # Regular expression for validating a hostname
    valid_hostname_regex = '^(([a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9\-]*[a-zA-Z0-9])\.)*([A-Za-z0-9]|[A-Za-z0-9][A-Za-z0-9\-]*[A-Za-z])$'

    if re.search(valid_hostname_regex, p_host):
        return True
    else:
        return False


def reverse_ip(p_ip):
    """Reverse the IP a the addr format.

    Args:
        p_ip (str): An IP address.

    Returns:
        str: The IP in reversed.
    """
    temp_list = p_ip.split('.')
    return temp_list[3] + "." + temp_list[2] + "." + temp_list[1] + "." + temp_list[0]


def rbl_dns_query(p_host):
    """Check if the provided IP is on an DNSBL list (blacklist) and print the output on STDOUT.

    Args:
        p_host (str): A hostname.

    Returns:
        bool: True if the IP is found a the blacklist.
    """
    is_listed = False
    try:
        myResolver.query(p_host, 'A')
        is_listed = True
    except dns.resolver.Timeout:
        print("Timeout No answers could be found in the specified lifetime.")
    except dns.resolver.NXDOMAIN:
        print("NXDOMAIN The query name does not exist.")
    except dns.resolver.YXDOMAIN:
        print("YXDOMAIN The query name is too long after DNAME substitution.")
    except dns.resolver.NoAnswer:
        print("NoAnswer The response did not contain an answer and raise_on_no_answer is True.")
    except dns.resolver.NoNameservers:
        print("NoNameservers No non-broken nameservers are available to answer the question.")
    except Exception as error:
        print(error)
    finally:
        return is_listed


def check_spam_list(p_ip):
    """Loop on the DNSBL list (blacklist) declared aboce and print the output on STDOUT.

    Args:
        p_ip (str): An IP address.
    """
    total_found = 0
    i = 1
    print("IP to analyse: {}\n".format(p_ip))
    host_to_check = reverse_ip(p_ip)
    for bl in dnsblList:
        print("{0} : {1} : ".format(i, bl), end='')
        try:
            if rbl_dns_query(host_to_check + "." + bl):
                print("BAD! This IP is listed here.")
                total_found += 1
        except Exception:
            pass
        i += 1

    print("\nTotal found = {}/{}\n".format(total_found, len(dnsblList)))
    if total_found > 0:
        raise SystemExit("This is BAD, this IP was found {} times.".format(total_found))
    else:
        print("This is GOOD, this IP was not found at all.\n")


def get_ip(p_host):
    """Return IP address of host.

    Args:
        p_host (str): The hostname to get its IP.

    Returns:
        str: host IP, if found.
    """
    try:
        query_result = myResolver.query(p_host, 'A')
        for result in query_result:
            return str(result)

    except dns.resolver.Timeout:
        raise SystemExit("Timeout No answers could be found in the specified lifetime.")
    except dns.resolver.NXDOMAIN:
        raise SystemExit("NXDOMAIN The query name does not exist.")
    except dns.resolver.YXDOMAIN:
        raise SystemExit("YXDOMAIN The query name is too long after DNAME substitution.")
    except dns.resolver.NoAnswer:
        raise SystemExit("NoAnswer The response did not contain an answer and raise_on_no_answer is True.")
    except dns.resolver.NoNameservers:
        raise SystemExit("NoNameservers No non-broken nameservers are available to answer the question.")
    except Exception as error:
        raise SystemExit(error)


if __name__ == '__main__':
    # First thing first, check if an argument exist, if not exit.
    if len(sys.argv) == 1:
        raise SystemExit('Error: no argument: it requires an IP or a hostname.')

    # Define the argument as arg1
    arg1: str = sys.argv[1]

    if arg1 == "--version":
        version()
        exit(0)

    if arg1 == "--help" or arg1 == "-h":
        helpme()
        exit(0)

    # Show things at the console
    print("\n{}    v{}\n".format(__title__, __version__))
    print('Number of DNSBL in the list: %s\n\n' % len(dnsblList))

    # Settings for the dns.resolver module
    myResolver = dns.resolver.Resolver()
    # If True (the default), the resolver instance is configured in the normal fashion for the operating system the
    # resolver is running on. (I.e. a /etc/resolv.conf file on POSIX systems and from the registry on Windows systems.)
    # So here, we turned this off.
    myResolver.default_resolver = dns.resolver.Resolver(configure=False)
    # Define your DNS resolvers here, or use Google's.
    myResolver.default_resolver.nameservers = ['8.8.8.8', '8.8.4.4']
    # The number of seconds to wait for a response from a server, before timing out.
    myResolver.timeout = 3
    # The total number of seconds to spend trying to get an answer to the question.
    myResolver.lifetime = 3

    try:
        # Check if the IP is valid, if applicable.
        isValidIP = validate_ip(arg1)

        # If it is an IP, do you stuff and quit...
        if isValidIP:
            check_spam_list(arg1)
            exit(0)

        # Check if the provided name is a valid hostname.
        isValidHostname = validate_hostname(arg1)

        # If the hostname is valid and it was not an IP, do you stuff...
        if isValidHostname and not isValidIP:
            print("Getting the IP for:", arg1)
            # DNS query to get the IP of the provided hostname.
            ip: str = get_ip(arg1)

            # If an IP was found.
            if ip:
                check_spam_list(ip)
                exit(0)
            else:
                raise SystemExit("Error: an IP has not been found for: %s" % arg1)

        if not isValidHostname and not isValidIP:
            raise SystemExit("Error: This argument is not a valid IP or hostname: %s" % arg1)

    except Exception as e:
        print(e)
