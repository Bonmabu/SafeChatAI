from pathlib import Path

p = Path(r".\main.py")
lines = p.read_text(encoding="utf-8").splitlines()

for i, line in enumerate(lines, 1):
    if (
        "@app.get(\"/customer/" in line
        or "@app.put(\"/customer/" in line
        or "@app.post(\"/customer/" in line
        or "@app.delete(\"/customer/" in line
        or "@app.get(\"/executive/" in line
        or "@app.put(\"/executive/" in line
        or "@app.post(\"/executive/" in line
        or "@app.delete(\"/executive/" in line
    ):
        print(f"{i:5}: {line}")
