import asyncio
import json
import logging

from bsv.fee_models.live_policy import LivePolicy
from bsv.http_client import default_http_client


async def main() -> None:
    logging.basicConfig(level=logging.INFO)
    logging.getLogger("bsv.fee_models.live_policy").setLevel(logging.DEBUG)

    policy = LivePolicy(cache_ttl_ms=0)
    live_rate = await policy.current_rate_sat_per_kb()
    print(f"Live fee rate: {live_rate} sat/kB")

    http_client = default_http_client()
    response = await http_client.get(
        policy.arc_policy_url,
        headers={"Accept": "application/json"},
        timeout=policy.request_timeout,
    )
    print(f"HTTP status: {response.status_code}")
    payload = response.json_data
    print("Policy payload:")
    print(json.dumps(payload, indent=2, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
