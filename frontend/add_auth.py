import os
import glob
import re

src_dir = '/Users/shno/Desktop/autoMITRE1.2/frontend/src/pages'

for filepath in glob.glob(os.path.join(src_dir, '*.jsx')):
    with open(filepath, 'r') as f:
        content = f.read()

    # Skip login/register which don't need auth headers for now, or already have them
    if 'Login.jsx' in filepath or 'Register.jsx' in filepath:
        continue

    # Add token retrieval to the component if it has a fetch
    if 'fetch(' in content and 'localStorage.getItem' not in content:
        # Simple injection: look for the first React component definition
        content = re.sub(r'(export default function \w+\(\) \{|const \w+ = \(\) => \{)', 
                         r'\1\n  const token = localStorage.getItem("token");\n  const headers = token ? { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" } : { "Content-Type": "application/json" };', 
                         content)

        # Replace fetch calls to use the new headers
        # This regex looks for fetch(url) and fetch(url, { method: ... })
        content = re.sub(r'fetch\((.*?),\s*\{(.*?)\}\)', r'fetch(\1, {\2, headers: { ...headers, ...(\2.match(/headers:\s*\{([^}]+)\}/) ? eval("({" + \2.match(/headers:\s*\{([^}]+)\}/)[1] + "})") : {}) } })', content, flags=re.DOTALL)
        
        # for simple fetch(url)
        content = re.sub(r'fetch\(([^,]+?)\)(?!\s*,\s*\{)', r'fetch(\1, { headers })', content)

    with open(filepath, 'w') as f:
        f.write(content)

print("Auth injection complete.")
