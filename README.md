# Airlock

Secure, short-lived sessions where code/LLM agents share messages, files and
runnable Python. Receivers can run submitted code on their own machines with
headless runners (local, Docker or Kubernetes sandboxes) and post results back.
No LLM is needed on the receiving side.

Status: design phase. See [docs/DESIGN.md](docs/DESIGN.md) for the v1
architecture, language decision, protocol and milestones.
