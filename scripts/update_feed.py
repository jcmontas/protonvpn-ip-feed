
#!/usr/bin/env python3

import ipaddress
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

ASNS = [
    212238, 62371, 9009, 199218, 209103, 60068, 33970,
    49981, 43350, 24961, 47869, 14061, 29066, 393886, 208172, 20860, 49367,
    12876, 18978, 46475, 136258, 63018, 40676, 63949, 62240, 21859, 63023, 1267,
    32489, 396190, 396356, 37153, 132335, 132825, 35758, 61493, 206991, 8728,
    3920, 51765, 60781, 30083, 394380, 27411, 13213, 396362, 30633, 137409,
    50979, 16276, 61272, 40021, 62563, 51167, 34989, 141995, 61254
]

OUTPUT = Path("protonvpn-ipv4.txt")
TEMP_OUTPUT = OUTPUT.with_suffix(".txt.tmp")

MINIMUM_PREFIX_COUNT = 10

MAX_WORKERS = 5
REQUEST_TIMEOUT = 45
MAX_ATTEMPTS = 3
RETRY_DELAYS = [5, 15]


def fetch_asn_prefixes(asn):
    params = urllib.parse.urlencode({
        "resource": f"AS{asn}"
    })

    url = (
        "https://stat.ripe.net/data/announced-prefixes/data.json?"
        + params
    )

    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "VPN-IP-Feed/2.0",
            "Accept": "application/json"
        }
    )

    last_error = None

    for attempt in range(1, MAX_ATTEMPTS + 1):

        try:
            print(
                f"[AS{asn}] Attempt {attempt}/{MAX_ATTEMPTS}",
                flush=True
            )

            with urllib.request.urlopen(
                request,
                timeout=REQUEST_TIMEOUT
            ) as response:

                result = json.loads(
                    response.read().decode("utf-8")
                )

            prefixes = result.get("data", {}).get("prefixes")

            if not isinstance(prefixes, list):
                raise RuntimeError(
                    f"Invalid RIPEstat response for AS{asn}"
                )

            accepted = set()

            for entry in prefixes:
                try:
                    network = ipaddress.ip_network(
                        entry["prefix"],
                        strict=False
                    )

                    if network.version != 4:
                        continue

                    if not network.is_global or network.prefixlen < 8:
                        print(
                            f"[AS{asn}] Rejected: {network}",
                            flush=True
                        )
                        continue

                    accepted.add(str(network))

                except (ValueError, KeyError, TypeError):
                    continue

            print(
                f"[AS{asn}] SUCCESS: {len(accepted)} prefixes",
                flush=True
            )

            return asn, accepted

        except urllib.error.HTTPError as error:

            if error.code != 429 and error.code < 500:
                raise

            last_error = error

        except (
            urllib.error.URLError,
            TimeoutError,
            socket.timeout,
            json.JSONDecodeError
        ) as error:

            last_error = error

        if attempt < MAX_ATTEMPTS:

            delay = RETRY_DELAYS[attempt - 1]

            print(
                f"[AS{asn}] Error: {last_error}. "
                f"Retrying in {delay}s...",
                flush=True
            )

            time.sleep(delay)

    raise RuntimeError(
        f"AS{asn} failed after {MAX_ATTEMPTS} attempts: "
        f"{last_error}"
    )


def main():

    print("=" * 55, flush=True)
    print("Starting VPN IPv4 feed generation", flush=True)
    print(f"Total ASNs: {len(ASNS)}", flush=True)
    print(f"Concurrent workers: {MAX_WORKERS}", flush=True)
    print("=" * 55, flush=True)

    results = {}
    errors = []

    with ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        futures = {
            executor.submit(fetch_asn_prefixes, asn): asn
            for asn in ASNS
        }

        completed = 0

        for future in as_completed(futures):

            asn = futures[future]
            completed += 1

            try:
                result_asn, prefixes = future.result()
                results[result_asn] = prefixes

                print(
                    f"PROGRESS: {completed}/{len(ASNS)} "
                    f"ASNs completed",
                    flush=True
                )

            except Exception as error:

                errors.append((asn, str(error)))

                print(
                    f"FAILED AS{asn}: {error}",
                    flush=True
                )

                print(
                    f"PROGRESS: {completed}/{len(ASNS)} "
                    f"ASNs completed",
                    flush=True
                )

    # Never publish if any ASN query failed
    if errors:

        print("\nERROR SUMMARY", flush=True)

        for asn, error in errors:
            print(f"AS{asn}: {error}", flush=True)

        raise RuntimeError(
            f"{len(errors)} ASN queries failed. "
            "Existing feed preserved."
        )

    if len(results) != len(ASNS):
        raise RuntimeError(
            "ASN result count mismatch. Existing feed preserved."
        )

    networks = set()

    print("\nASN SUMMARY", flush=True)

    for asn in ASNS:
        count = len(results[asn])
        networks.update(results[asn])

        print(f"AS{asn}: {count}", flush=True)

    if len(networks) < MINIMUM_PREFIX_COUNT:
        raise RuntimeError(
            f"Only {len(networks)} prefixes collected. "
            "Existing feed preserved."
        )

    sorted_networks = sorted(
        networks,
        key=lambda item: (
            int(ipaddress.ip_network(item).network_address),
            ipaddress.ip_network(item).prefixlen
        )
    )

    # Write to temporary file first
    TEMP_OUTPUT.write_text(
        "\n".join(sorted_networks) + "\n",
        encoding="utf-8"
    )

    # Atomic replacement after successful collection
    TEMP_OUTPUT.replace(OUTPUT)

    print("\n" + "=" * 55, flush=True)
    print("FEED GENERATION SUCCESSFUL", flush=True)
    print(f"ASNs processed: {len(results)}", flush=True)
    print(
        f"Total unique IPv4 prefixes: {len(sorted_networks)}",
        flush=True
    )
    print(f"Output: {OUTPUT}", flush=True)
    print(
        "Generated:",
        datetime.now(timezone.utc).isoformat(),
        flush=True
    )
    print("=" * 55, flush=True)


if __name__ == "__main__":
    main()
