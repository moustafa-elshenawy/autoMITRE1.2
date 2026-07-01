import re

with open('presentation/src/data/slides.ts', 'r') as f:
    text = f.read()

# First, add the new widgets to the SlideWidget type
# Find the line | 'data_flow_diagram' and insert the new ones after it
text = re.sub(
    r"(\|\s*'data_flow_diagram')",
    r"\1\n  | 'semantic_reranker'\n  | 'threat_severity'",
    text
)

# We will just parse the file and rebuild it
# But writing it out manually might be easier. Let's just output the whole file.

import sys
sys.exit(0)
