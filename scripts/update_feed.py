
#!/usr/bin/env python3

import ipaddress
import json
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ASNS = [
    212238, 62371, 9009, 199218, 209103, 60068, 33970,
    49981, 43350, 24961, 47869, 14061, 29066, 393886
]

OUTPUT = Path("protonvpn-ipv4.txt")
MINIMUM_PREFIX_COUNT = 10

def fetch_asn_prefixes(asn):
    params = urllib.parse.urlencode({"resource": f"AS{asn}"})
    url = (
        "https://stat.ripe.net/data/announced-prefixes/data.json?"
        + params
    )

    request = urllib.request.Request(
        url,
        headers={"User-Agent": "ProtonVPN-IP-Feed/1.0"}
    )

    with urllib.request.urlopen(request, timeout=45) as response:
        result = json.loads(response.read().decode("utf-8"))

    prefixes = result.get("data", {}).get("prefixes")

    if not isinstance(prefixes, list):
        raise RuntimeError(f"Invalid RIPEstat response for AS{asn}")

    return prefixes


def main():
    networks = set()
    total_by_asn = {}

    print("Starting ProtonVPN IPv4 feed generation")

    for asn in ASNS:
        print(f"Querying AS{asn}...")

        entries = fetch_asn_prefixes(asn)
        accepted = 0

        for entry in entries:
            try:
                network = ipaddress.ip_network(
                    entry["prefix"], strict=False
                )

                # IPv4 only
                if network.version != 4:
                    continue

                # Exclude non-global and excessively broad prefixes
                if not network.is_global or network.prefixlen < 8:
                    print(f"Rejected suspicious prefix: {network}")
                    continue

                networks.add(str(network))
                accepted += 1

            except (ValueError, KeyError, TypeError):
                continue

        total_by_asn[asn] = accepted
        print(f"AS{asn}: {accepted} accepted prefixes")

    if len(networks) < MINIMUM_PREFIX_COUNT:
        raise RuntimeError(
            f"Only {len(networks)} prefixes collected. "
            "Refusing to publish incomplete feed."
        )

    sorted_networks = sorted(
        networks,
        key=lambda item: (
            int(ipaddress.ip_network(item).network_address),
            ipaddress.ip_network(item).prefixlen
        )
    )

    # Write only after all ASN queries have completed successfully
    OUTPUT.write_text(
        "\n".join(sorted_networks) + "\n",
        encoding="utf-8"
    )

    print("\nASN SUMMARY")
    for asn, count in total_by_asn.items():
        print(f"AS{asn}: {count}")

    print(f"\nTotal unique IPv4 prefixes: {len(sorted_networks)}")
    print(f"Output: {OUTPUT}")

    print(
        "Generated:",
        datetime.now(timezone.utc).isoformat()
    )


if __name__ == "__main__":
    main()
