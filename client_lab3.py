import asyncio
from lab3 import run_node, load_members

if __name__ == "__main__":
    member = load_members()
    asyncio.run(run_node("keys/sadi.pem", 8095, member, is_registrar=False))
