import os
import time
from ollama import Client

client = Client(host=os.environ.get('OLLAMA_HOST', 'http://192.168.56.1:11434'))

prompts = [
    "What is phishing?",
    "List 5 red flags in a suspicious email.",
    "Explain SPF, DKIM, and DMARC in one paragraph each.",
]

print(f"{'time':>8}  {'tokens':>8}  prompt")
print("-" * 60)

total_time = 0
for p in prompts:
    start = time.time()
    r = client.generate(model='llama3.2', prompt=p)
    elapsed = time.time() - start
    total_time += elapsed
    tokens = len(r['response'].split())
    print(f"{elapsed:7.2f}s  {tokens:>8}  {p[:40]}")

print("-" * 60)
print(f"Total: {total_time:.2f}s across {len(prompts)} prompts "
      f"(avg {total_time/len(prompts):.2f}s each)")
