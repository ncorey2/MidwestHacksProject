import sys
import ollama
def triage(findings):
    out = {}
    for i in range(0, len(findings), 5):             # smaller batches for local models
        batch = [{"id": i + n, **f, "snippet": snippet(f)}
                 for n, f in enumerate(findings[i:i + 5])]
        try:
            resp = ollama.chat(
                model=MODEL,
                format="json",                        # forces valid JSON output
                options={"temperature": 0, "num_ctx": 8192},
                messages=[
                    {"role": "system", "content": SYSTEM +
                     ' Return a JSON object: {"results": [ ... ]}.'},
                    {"role": "user", "content": json.dumps(batch)},
                ],
            )
            data = json.loads(resp["message"]["content"])
            for item in data.get("results", []):
                out[item["id"]] = item
        except Exception as e:
            print(f"Batch starting at {i} failed ({e}); left untriaged")
    return out