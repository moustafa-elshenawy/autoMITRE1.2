import os

base_dir = "/Users/shno/Desktop/autoMITRE1.2"
frontend_src = os.path.join(base_dir, "frontend", "src")

for root, dirs, files in os.walk(frontend_src):
    for file in files:
        if file.endswith((".jsx", ".js", ".tsx", ".ts")):
            path = os.path.join(root, file)
            with open(path, "r", encoding="utf-8") as f:
                content = f.read()
            
            new_content = content.replace("localhost:8000", "localhost:8080")
            new_content = new_content.replace("127.0.0.1:8000", "127.0.0.1:8080")
            
            if content != new_content:
                with open(path, "w", encoding="utf-8") as f:
                    f.write(new_content)
                print(f"Updated ports in: {file}")
