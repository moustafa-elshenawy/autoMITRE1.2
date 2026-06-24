from bs4 import BeautifulSoup

def test_parser(file_path):
    with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
        soup = BeautifulSoup(f.read(), "html.parser")
    
    threats = soup.find_all("div", class_="threat")
    print(f"Found {len(threats)} threat divs.")
    
    for i, t in enumerate(threats[:3]):
        title_tag = t.find("h4")
        title = title_tag.get_text(strip=True) if title_tag else "No Title"
        print(f"\nThreat {i+1}: {title}")
        
        table = t.find("table")
        if table:
            for row in table.find_all("tr"):
                cells = row.find_all(["th", "td"])
                if len(cells) >= 2:
                    k = cells[0].get_text(strip=True).rstrip(":")
                    v = cells[1].get_text(strip=True)
                    print(f"  {k}: {v}")

test_parser("/Users/shno/Downloads/Custom Report.htm.html")
