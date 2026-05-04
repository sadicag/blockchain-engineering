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

DIFFICULTY = 28

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

def check_difficulty(digest: bytes, bits: int) -> bool:
    full_bytes, extra_bits = divmod(bits, 8)
    if any(b != 0 for b in digest[:full_bytes]):
        return False
    if extra_bits == 0:
        return True
    return digest[full_bytes] < (1 << (8 - extra_bits))


def mine_pow(email: str, github_url: str, difficulty: int = DIFFICULTY) -> int:
    prefix = email.encode("utf-8") + b"\n" + github_url.encode("utf-8") + b"\n"
    t0 = time.time()
    report_every = 2_000_000
    print(f"\nMining PoW (difficulty={difficulty} bits) ...")
    print(f"    prefix = {prefix!r}")
    nonce = 0
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
            print(f"   ... {nonce:,} hashes  ({rate/1e6:.2f} Mh/s)  ETA ~{eta:.0f}s total")


def verify_pow(email: str, github_url: str, nonce: int, difficulty: int = DIFFICULTY) -> tuple[bool, str]:
    data = (email.encode("utf-8") + b"\n" +
            github_url.encode("utf-8") + b"\n" +
            struct.pack(">q", nonce))
    digest = hashlib.sha256(data).digest()
    return check_difficulty(digest, difficulty), digest.hex()

# --- Community ---

class Lab1Community(Community):
    community_id = COMMUNITY_ID

    def __init__(self, settings: CommunitySettings) -> None:
        super().__init__(settings)
        self.email = settings.email
        self.github_url = settings.github_url
        self.nonce = settings.nonce
        self._done_event = asyncio.Event()
        self._submitted = False
        self.add_message_handler(ResponsePayload, self.on_response)

    def _is_server(self, peer: Peer) -> bool:
        key_bin = peer.public_key.key_to_bin()
        match = (key_bin == SERVER_PUBLIC_KEY_BIN)
        if not match and key_bin[:10] == SERVER_PUBLIC_KEY_BIN[:10]:
            # Same prefix but different full key — log for debugging
            print(f"[key mismatch] peer {peer.address}")
            print(f"  got : {key_bin.hex()}")
            print(f"  want: {SERVER_PUBLIC_KEY_BIN.hex()}")
        return match

    def peer_added(self, peer: Peer) -> None:
        super().peer_added(peer)
        if self._is_server(peer):
            print(f"\n>>> SERVER found via peer_added at {peer.address}")
            if not self._submitted:
                self._submitted = True
                print("    _submitted = True (peer_added)")
                fut = asyncio.ensure_future(self._send_submission(peer))
                fut.add_done_callback(self._on_send_done)
            else:
                print("    (already submitted, skipping)")
        else:
            print(f"[peer] {peer.address}  key={peer.public_key.key_to_bin().hex()[:20]}...")

    def _on_send_done(self, fut: asyncio.Future) -> None:
        if fut.exception():
            print(f"\n[ERROR] _send_submission raised: {fut.exception()}")

    async def _send_submission(self, server: Peer) -> None:
        await asyncio.sleep(1.0)
        print(f"\nSending submission to {server.address} ...")
        print(f"   email      = {self.email!r}")
        print(f"   github_url = {self.github_url!r}")
        print(f"   nonce      = {self.nonce}")

        payload = SubmissionPayload(
            email=self.email,
            github_url=self.github_url,
            nonce=self.nonce,
        )

        attempt = 0
        while not self._done_event.is_set():
            attempt += 1
            print(f"   [attempt {attempt}] ez_send → {server.address}")
            self.ez_send(server, payload)
            # Wait up to 15s for a response before retrying
            try:
                await asyncio.wait_for(asyncio.shield(self._done_event.wait()), timeout=15.0)
                break
            except asyncio.TimeoutError:
                if attempt >= 10:
                    print("   [give up] 10 attempts with no response")
                    break
                print(f"   [no response yet, retrying...]")

    @lazy_wrapper(ResponsePayload)
    def on_response(self, peer: Peer, payload: ResponsePayload) -> None:
        if not self._is_server(peer):
            print(f"Ignoring response from non-server peer {peer.address}")
            return
        icon = "SUCCESS" if payload.success else "FAILURE"
        print(f"\n{'='*50}")
        print(f"{icon} — Server response:")
        print(f"   success = {payload.success}")
        print(f"   message = {payload.message!r}")
        print('='*50)
        self._done_event.set()

    async def poll_for_server(self) -> None:
        """
        Fallback: periodically scan already-verified peers in case
        peer_added fired before the community was fully initialized.
        Also re-triggers send if we found the server but got no response.
        """
        for _ in range(100):
            await asyncio.sleep(3)
            if self._done_event.is_set():
                return
            for peer in list(self.network.verified_peers):
                if self._is_server(peer):
                    if not self._submitted:
                        print(f"\n[poll] SERVER found at {peer.address} — sending now")
                        self._submitted = True
                        print("    _submitted = True (poll)")
                        fut = asyncio.ensure_future(self._send_submission(peer))
                        fut.add_done_callback(self._on_send_done)
                    return

    async def wait_for_response(self, timeout: float = 300.0) -> None:
        try:
            await asyncio.wait_for(self._done_event.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            print(f"\nNo response after {timeout:.0f}s.")
            print("Possible causes:")
            print("  1. Server not reachable from your network")
            print("  2. Server key mismatch (check key in log above)")
            print("  3. Packet signing issue — ensure ez_send is used")

# --- Run ---

async def run(email: str, github_url: str, key_file: str, nonce: int | None) -> None:
    if nonce is None:
        nonce = mine_pow(email, github_url)
    else:
        ok, h = verify_pow(email, github_url, nonce)
        if ok:
            print(f"Pre-computed nonce verified. SHA256 = {h}")
        else:
            print(f"Nonce {nonce} does NOT satisfy difficulty={DIFFICULTY}! SHA256 = {h}")
            sys.exit(1)

    # Sanity-check the server key constant
    assert len(SERVER_PUBLIC_KEY_BIN) == 74, f"Bad server key length: {len(SERVER_PUBLIC_KEY_BIN)}"
    print(f"\nServer key ({len(SERVER_PUBLIC_KEY_BIN)} bytes): {SERVER_PUBLIC_KEY_BIN.hex()[:20]}...")

    builder = (
        ConfigBuilder()
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
    print("Keep this .pem file safe — it is your permanent identity!\n")

    community: Lab1Community = ipv8.get_overlay(Lab1Community)

    # Start the polling fallback alongside the event-driven path
    asyncio.ensure_future(community.poll_for_server())

    async def debug_loop():
        for _ in range(30):
            await asyncio.sleep(10)
            if community._done_event.is_set():
                return
            peers = list(community.network.verified_peers)
            print(f"\n[debug] {len(peers)} community peers:")
            server_seen = False
            for p in peers:
                key = p.public_key.key_to_bin()
                is_srv = (key == SERVER_PUBLIC_KEY_BIN)
                tag = " *** SERVER ***" if is_srv else ""
                print(f"  {p.address}  key={key.hex()[:20]}...{tag}")
                if is_srv:
                    server_seen = True
            if not server_seen:
                print("  (server not yet seen in community peers)")

    asyncio.ensure_future(debug_loop())
    await community.wait_for_response(timeout=300.0)
    await ipv8.stop()
    print("\nDone.")


def main() -> None:
    parser = argparse.ArgumentParser(description="Lab 1 — IPv8 Proof-of-Work client")
    parser.add_argument("--email",  required=True)
    parser.add_argument("--github", required=True)
    parser.add_argument("--key",    default="lab1_identity.pem")
    parser.add_argument("--nonce",  type=int, default=None)
    args = parser.parse_args()

    email = args.email.strip()
    github_url = args.github.strip()

    if not (email.endswith("@tudelft.nl") or email.endswith("@student.tudelft.nl")):
        print(f"ERROR: Email must end in @tudelft.nl or @student.tudelft.nl  (got: {email!r})")
        sys.exit(1)
    if any(c in email for c in ("\n", " ")):
        print("ERROR: Email must not contain newlines or spaces.")
        sys.exit(1)
    if not github_url or len(github_url) > 512 or any(c in github_url for c in (" ", "\n", "\r", "\t")):
        print("ERROR: GitHub URL must be non-empty, ≤512 chars, no whitespace/control chars.")
        sys.exit(1)
    if args.nonce is not None and args.nonce < 0:
        print("ERROR: Nonce must be a non-negative integer.")
        sys.exit(1)

    logging.basicConfig(level=logging.ERROR)
    for name in ("asyncio", "ipv8", "ipv8.community", "ipv8.peerdiscovery",
                 "ipv8.messaging", "ipv8_service"):
        logging.getLogger(name).setLevel(logging.ERROR)

    asyncio.run(run(email=email, github_url=github_url, key_file=args.key, nonce=args.nonce))


if __name__ == "__main__":
    main()
