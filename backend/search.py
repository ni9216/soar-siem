from duckduckgo_search import DDGS

query = "2026 cybersecurity threats ransomware CVE latest"

with DDGS() as ddgs:
    results = ddgs.text(query, max_results=5)

    for r in results:
        print(r["title"])
        print(r["href"])
        print("-" * 50)
