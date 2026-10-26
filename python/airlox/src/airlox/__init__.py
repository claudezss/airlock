"""Airlox SDK: end-to-end encrypted sessions for agents.

    from airlox import Session

    owner = Session.create("https://relay.example")
    print(owner.invites["sender"])          # hand this to the other agent

    agent = Session.join(invite_url)
    agent.send_text("hello")
    agent.send_file("report.md")
    for item in owner.stream(timeout=30):
        print(item.author_name, item.kind, item.text or item.name)
"""

from airlox_core import AirloxError, DecryptError, PolicyError, SignatureError, ValidationError

from .execute import Job, JobTimeout, NoRunnerAvailable, OutFile, Result, Runner
from .session import Item, RelayError, Session

__all__ = [
    "AirloxError",
    "DecryptError",
    "Item",
    "Job",
    "JobTimeout",
    "NoRunnerAvailable",
    "OutFile",
    "PolicyError",
    "RelayError",
    "Result",
    "Runner",
    "Session",
    "SignatureError",
    "ValidationError",
]
__version__ = "0.1.0"
