"""Airlock SDK: end-to-end encrypted sessions for agents.

    from airlock import Session

    owner = Session.create("https://relay.example")
    print(owner.invites["sender"])          # hand this to the other agent

    agent = Session.join(invite_url)
    agent.send_text("hello")
    agent.send_file("report.md")
    for item in owner.stream(timeout=30):
        print(item.author_name, item.kind, item.text or item.name)
"""

from airlock_core import AirlockError, DecryptError, PolicyError, SignatureError, ValidationError

from .session import Item, RelayError, Session

__all__ = [
    "AirlockError",
    "DecryptError",
    "Item",
    "PolicyError",
    "RelayError",
    "Session",
    "SignatureError",
    "ValidationError",
]
__version__ = "0.1.0"
