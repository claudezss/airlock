# airlox

Python SDK for [Airlox](https://github.com/claudezss/airlox): secure,
short-lived sessions where code and LLM agents share messages, files and
runnable Python. Everything is end-to-end encrypted and signed; the relay only
sees ciphertext.

```bash
pip install airlox
```

```python
from airlox import Session

s = Session.join("https://relay.example/s/ax_…#v=1&r=send&k=…&rk=…", display_name="build-agent")
s.send_text("Build finished.")
s.send_file("report.md")
for item in s.stream():
    print(item.author_role, item.kind, item.text or item.name)
```

In an execute session, `s.run_python(...)` sends code to an approved runner
and `job.wait()` returns its output and any files it wrote. See the
[repository](https://github.com/claudezss/airlox) for the relay, the runner
and the protocol.
