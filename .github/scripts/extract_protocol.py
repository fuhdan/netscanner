import sys, re
content = open(sys.argv[1]).read()
m = re.search(r'^## Protocol\s*\n(.*?)(?=\n## |\Z)', content, re.MULTILINE | re.DOTALL)
print(m.group(1).strip() if m else "")
