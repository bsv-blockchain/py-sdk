import asyncio
import os
from pathlib import Path
from typing import Dict, Optional, Union

from bsv import (
    ChainTracker,
    HttpClient,
    PrivateKey,
    Transaction,
    TransactionInput,
    TransactionOutput,
    default_http_client,
)

"""
This example demonstrates how to use a custom ChainTracker implementation to
verify Merkle proofs against a local Block Headers Service, formerly known as 'Pulse'.

The code shows how to integrate a block header validation service with the BEEF
transaction verification process. This is crucial for SPV (Simplified Payment Verification)
checks, on which many wallets rely upon.

Setup:
1. Copy .env.local.example to .env.local
2. Add your BHS API key to the BHS_API_KEY environment variable in .env.local
3. Run this script: python examples/custom_chaintracker.py
"""


def load_env_file():
    """Load environment variables from .env.local file if it exists."""
    env_file = Path(__file__).parent.parent / ".env.local"
    if env_file.exists():
        with open(env_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    key, value = line.split("=", 1)
                    os.environ[key.strip()] = value.strip()


class BHSChainTracker(ChainTracker):

    def __init__(
        self,
        URL: str,
        api_key: Optional[str] = None,
        http_client: Optional[HttpClient] = None,
    ):
        self.URL = URL
        self.http_client = http_client if http_client else default_http_client()
        self.api_key = api_key

    async def is_valid_root_for_height(self, root: str, height: int) -> bool:
        request_options = {
            "method": "POST",
            "headers": self.get_headers(),
            "data": [{"merkleRoot": root, "blockHeight": height}],
        }

        response = await self.http_client.fetch(f"{self.URL}/api/v1/chain/merkleroot/verify", request_options)
        if response.ok:
            print(response.json())
            return response.json()["data"]["confirmationState"] == "CONFIRMED"
        elif response.status_code == 404:
            return False
        else:
            raise ValueError(f"Failed to verify merkleroot for height {height}: {response.json()}")

    def get_headers(self) -> dict[str, str]:
        headers = {
            "Accept": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"
        return headers


async def main():
    # Load environment variables from .env.local
    load_env_file()

    # Get API key from environment variable
    api_key = os.getenv("BHS_API_KEY")
    if not api_key:
        raise ValueError("BHS_API_KEY environment variable is required. Please set it in .env.local file.")

    BEEF_hex = "0100beef01fe636d0c0007021400fe507c0c7aa754cef1f7889d5fd395cf1f785dd7de98eed895dbedfe4e5bc70d1502ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e010b00bc4ff395efd11719b277694cface5aa50d085a0bb81f613f70313acd28cf4557010400574b2d9142b8d28b61d88e3b2c3f44d858411356b49a28a4643b6d1a6a092a5201030051a05fc84d531b5d250c23f4f886f6812f9fe3f402d61607f977b4ecd2701c19010000fd781529d58fc2523cf396a7f25440b409857e7e221766c57214b1d38c7b481f01010062f542f45ea3660f86c013ced80534cb5fd4c19d66c56e7e8c5d4bf2d40acc5e010100b121e91836fd7cd5102b654e9f72f3cf6fdbfd0b161c53a9c54b12c841126331020100000001cd4e4cac3c7b56920d1e7655e7e260d31f29d9a388d04910f1bbd72304a79029010000006b483045022100e75279a205a547c445719420aa3138bf14743e3f42618e5f86a19bde14bb95f7022064777d34776b05d816daf1699493fcdf2ef5a5ab1ad710d9c97bfb5b8f7cef3641210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013e660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000001000100000001ac4e164f5bc16746bb0868404292ac8318bbac3800e4aad13a014da427adce3e000000006a47304402203a61a2e931612b4bda08d541cfb980885173b8dcf64a3471238ae7abcd368d6402204cbf24f04b9aa2256d8901f0ed97866603d2be8324c2bfb7a37bf8fc90edd5b441210263e2dee22b1ddc5e11f6fab8bcd2378bdd19580d640501ea956ec0e786f93e76ffffffff013c660000000000001976a9146bfd5c7fbe21529d45803dbcf0c87dd3c71efbc288ac0000000000"

    tx = Transaction.from_beef(BEEF_hex)
    print("TXID:", tx.txid())

    verified = await tx.verify(BHSChainTracker(URL="http://localhost:8080", api_key=api_key))
    print("BEEF verified:", verified)
    assert verified


asyncio.run(main())
