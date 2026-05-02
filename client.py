import asyncio
import dataclasses
import hashlib
import logging
import struct
import sys
import time
import argparse

from ipv8.community import Community, CommunitySettings
from ipv8.configuration import (
    ConfigBuilder, Strategy, WalkerDefinition,
    BootstrapperDefinition, Bootstrapper,
)
from ipv8.lazy_community import lazy_wrapper
from ipv8.messaging.payload_dataclass import DataClassPayloadWID
from ipv8.peer import Peer
from ipv8_service import IPv8

# --- Constants ---

COMMUNITY_ID = bytes.fromhex("2c1cc6e35ff484f99ebdfb6108477783c0102881")

SERVER_PUBLIC_KEY_BIN = bytes.fromhex(
    "4c69624e61434c504b3a86b23934a28d669c390e2d1fc0b0870706c4591cc0cb"
    "178bc5a811da6d87d27ef319b2638ef60cc8d119724f4c53a1ebfad919c3ac41"
    "36c501ce5c09364e0ebb"
)

DIFFICULTY = 28 # The leading zero bits

# --- Payloads ---

@dataclasses.dataclass
class SubmissionPayload(DataClassPayloadWID):
    msg_id = 1
    email: str
    github_url: str
    nonce: int


@dataclasses.dataclass
class ResponsePayload(DataClassPayloadWID):
    msg_id = 2
    success: bool
    message: str

# --- Proof of Work ---

def check_difficulty(
    digest: bytes, 
    bits: int
) -> bool:

    full_bytes, extra_bits = divmod(bits, 8)
    if any(b != 0 for b in digest[:full_bytes]):
        return False
    if extra_bits == 0:
        return True
    return digest[full_bytes] < (1 << (8 - extra_bits))


def mine_pow(
    email: str, 
    github_url: str, 
    difficulty: int = DIFFICULTY
) -> int:

    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    t0 = time.time()
    report_every = 2_000_000
    print(f"\nMining PoW (difficulty={difficulty} bits) ...")
    print(f"    prefix = {prefix!r}")
    nonce = 0

    # Start the mining!
    while True:
        data = prefix + struct.pack(">q", nonce)
        digest = hashlib.sha256(data).digest()
        if check_difficulty(digest, difficulty):
            elapsed = time.time() - t0
            print(f"\nFound nonce = {nonce}")
            print(f"   {nonce:,} iterations in {elapsed:.1f}s")
            print(f"   SHA256 = {digest.hex()}")
            return nonce
        nonce += 1
        if nonce % report_every == 0:
            elapsed = time.time() - t0
            rate = nonce / elapsed
            eta = (2 ** difficulty) / rate
            print(f"   ... {nonce:,} hashes  ({rate/1e6:.2f} Mh/s)  ETA around {eta:.0f}s total")

def verify_pow(
    email: str, 
    github_url: str, 
    nonce: int,
    difficulty: int = DIFFICULTY
) -> tuple[bool, str]:

    data = (email.encode("utf-8") + b"\n" +
            github_url.encode("utf-8") + b"\n" +
            struct.pack(">q", nonce))
    digest = hashlib.sha256(data).digest()
    return check_difficulty(digest, difficulty), digest.hex()

# --- Community ---

class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(
        self, settings: CommunitySettings,
    ) -> None:

        super().__init__(settings)
        self.email = settings.email
        self.github_url = settings.github_url
        self.nonce = settings.nonce
        self._submitted = False
        self._done_event = asyncio.Event()
        self.add_message_handler(ResponsePayload, self.on_response)

    def peer_added(
        self, 
        peer: Peer
    ) -> None:

        super().peer_added(peer)
        if peer.public_key.key_to_bin() == SERVER_PUBLIC_KEY_BIN:
            print(f"\nServer peer found at {peer.address}")
            if not self._submitted:
                self._submitted = True
                asyncio.ensure_future(self._send_submission(peer))
        else:
            print(f"Discovered peer {peer.address} (not the server, ignoring)")

    async def _send_submission(
        self, 
        server: Peer
    ) -> None:

        print(f"\nSending submission …")
        print(f"   email      = {self.email!r}")
        print(f"   github_url = {self.github_url!r}")
        print(f"   nonce      = {self.nonce}")
        self.ez_send(server, SubmissionPayload(
            email=self.email,
            github_url=self.github_url,
            nonce=self.nonce,
        ))
        print("Sent. Waiting for response …")

    @lazy_wrapper(ResponsePayload)
    def on_response(
        self, 
        peer: Peer, 
        payload: ResponsePayload
    ) -> None:

        if peer.public_key.key_to_bin() != SERVER_PUBLIC_KEY_BIN:
            print(f"Ignoring response from non-server peer {peer.address}")
            return

        icon = "SUCCESS" if payload.success else "FAILURE"
        print(f"\n{icon} Server response:")
        print(f"   success = {payload.success}")
        print(f"   message = {payload.message!r}")
        self._done_event.set()

    async def wait_for_response(
        self, 
        timeout: float = 180.0
    ) -> None:

        try:
            await asyncio.wait_for(self._done_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            print(f"\nNo response after {timeout:.0f}s. Check connectivity.")

# --- Run ---
async def run(
    email: str, 
    github_url: str,
    key_file: str,
    nonce: int | None
) -> None:

    if nonce is None:
        nonce = mine_pow(email, github_url)
    else:
        ok, h = verify_pow(email, github_url, nonce)
        if ok:
            print(f"Pre-computed nonce verified. SHA256 = {h}")
        else:
            print(f"Nonce {nonce} does NOT satisfy difficulty={DIFFICULTY}! SHA256 = {h}")
            sys.exit(1)

    builder = (
        ConfigBuilder() # Also could be clean=True
        .add_key("my_key", "curve25519", key_file)
        .set_port(0)
        .set_address("0.0.0.0")
        .set_log_level("ERROR")
        .set_working_directory(".")
        .set_walker_interval(0.5)
        .add_overlay(
            "Lab1Community", "my_key",
            walkers=[WalkerDefinition(Strategy.RandomWalk, 20, {"timeout": 3.0})],
            bootstrappers=[BootstrapperDefinition(
                Bootstrapper.DispersyBootstrapper,
                {
                    "ip_addresses": [
                        ("130.161.119.206", 6421), ("130.161.119.206", 6422),
                        ("131.180.27.155",  6423),  ("131.180.27.156",  6424),
                        ("131.180.27.161",  6427),  ("131.180.27.161",  6521),
                        ("131.180.27.161",  6522),  ("131.180.27.162",  6523),
                        ("131.180.27.162",  6524),  ("130.161.119.215", 6525),
                        ("130.161.119.215", 6526),  ("130.161.119.201", 6527),
                        ("130.161.119.201", 6528),
                    ],
                    "dns_addresses": [
                        ("dispersy1.tribler.org", 6421), ("dispersy1.st.tudelft.nl", 6421),
                        ("dispersy2.tribler.org", 6422), ("dispersy2.st.tudelft.nl", 6422),
                        ("dispersy3.tribler.org", 6423), ("dispersy3.st.tudelft.nl", 6423),
                    ],
                    "bootstrap_timeout": 30.0,
                }
            )],
            initialize={"email": email, "github_url": github_url, "nonce": nonce},
            on_start=[],
        )
    )

    ipv8 = IPv8(builder.finalize(), extra_communities={"Lab1Community": Lab1Community})
    await ipv8.start()
    print(f"\nIPv8 started. Key file: {key_file}")
    print("Keep this .pem file safe - it is your permanent identity!\n")

    community: Lab1Community = ipv8.get_overlay(Lab1Community)
    print("Discovering server peer ...")
    await community.wait_for_response(timeout=180.0)
    await ipv8.stop()
    print("\nDone.")

def main() -> None:

    parser = argparse.ArgumentParser(
        description="Lab 1 — IPv8 Proof-of-Work client",
        formatter_class=argparse.RawDescriptionHelpFormatter,

        epilog="""
Examples:
  python lab1_client.py \\
      --email j.doe@student.tudelft.nl \\
      --github https://github.com/jdoe/lab1-ipv8

  # Re-submit with a saved nonce (skips mining):
  python lab1_client.py \\
      --email j.doe@student.tudelft.nl \\
      --github https://github.com/jdoe/lab1-ipv8 \\
      --nonce 123456789
""")
    parser.add_argument("--email",  required=True, help="Your TU Delft email address")
    parser.add_argument("--github", required=True, help="Public GitHub repo URL for this lab")
    parser.add_argument("--key",    default="lab1_identity.pem",
                        help="Path to .pem key file (created on first run)")
    parser.add_argument("--nonce",  type=int, default=None,
                        help="Use a pre-computed nonce instead of mining")
    args = parser.parse_args()

    email = args.email.strip()
    github_url = args.github.strip()

    if not (email.endswith("@tudelft.nl") or email.endswith("@student.tudelft.nl")):
        print(f"ERROR: Email must end in @tudelft.nl or @student.tudelft.nl  (got: {email!r})")
        sys.exit(1)
    if any(c in email for c in ("\n", " ")):
        print("ERROR: Email must not contain newlines or spaces.")
        sys.exit(1)
    if not github_url or len(github_url) > 512 or any(c in github_url for c in (" ","\n","\r","\t")):
        print("ERROR: GitHub URL must be non-empty, ≤ 512 chars, no whitespace/control chars.")
        sys.exit(1)
    if args.nonce is not None and args.nonce < 0:
        print("ERROR: Nonce must be a non-negative integer.")
        sys.exit(1)

    logging.basicConfig(level=logging.ERROR)
    for name in ("asyncio", "ipv8", "ipv8.community", "ipv8.peerdiscovery",
                 "ipv8.messaging", "ipv8_service"):
        logging.getLogger(name).setLevel(logging.ERROR)

    asyncio.run(run(email=email, github_url=github_url,
                    key_file=args.key, nonce=args.nonce))

if __name__ == "__main__":
    main()
