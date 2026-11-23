from dotenv import load_dotenv
load_dotenv()

import os
import requests

r = requests.get(
    "https://api.groq.com/openai/v1/models",
    headers={"Authorization": f"Bearer {os.environ['GROQ_API_KEY']}"},
)
r.raise_for_status()

for m in sorted(r.json()["data"], key=lambda m: m["id"]):
    if "whisper" in m["id"] or "tts" in m["id"]:
        continue
    print(m["id"], "| active:", m.get("active"), "| context:", m.get("context_window"))