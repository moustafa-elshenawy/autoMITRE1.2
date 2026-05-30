import os

base_dir = "/Users/shno/Desktop/autoMITRE1.2"

# 1. Update frontend files (replace localhost:8000 with localhost:8080)
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

# 2. Update backend/main.py (port=8080)
main_py_path = os.path.join(base_dir, "backend", "main.py")
with open(main_py_path, "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("port=8000", "port=8080")
with open(main_py_path, "w", encoding="utf-8") as f:
    f.write(content)
print("Updated backend/main.py")

# 3. Update run.sh
run_sh_path = os.path.join(base_dir, "run.sh")
with open(run_sh_path, "r", encoding="utf-8") as f:
    content = f.read()
content = content.replace("--port 8000", "--port 8080")
content = content.replace("npm run dev", "npm run dev -- --port 5174")
content = content.replace("localhost:8000", "localhost:8080")
content = content.replace("localhost:5173", "localhost:5174")
with open(run_sh_path, "w", encoding="utf-8") as f:
    f.write(content)
print("Updated run.sh")
