import sqlite3

db = r"C:\Users\KISTO\AppData\Local\FishPoker\commondb\common.db"
conn = sqlite3.connect(db)
c = conn.cursor()

c.execute("SELECT name FROM sqlite_master WHERE type='table'")
tables = c.fetchall()
print("Tables:", tables)

for (tname,) in tables:
    print(f"\n=== {tname} ===")
    c.execute(f"SELECT * FROM [{tname}]")
    cols = [d[0] for d in c.description]
    print("Columns:", cols)
    for row in c.fetchall():
        # Truncate long binary values for display
        display = []
        for v in row:
            if isinstance(v, bytes) and len(v) > 100:
                display.append(f"<bytes len={len(v)}>")
            elif isinstance(v, str) and len(v) > 200:
                display.append(v[:200] + "...")
            else:
                display.append(v)
        print(display)

conn.close()
