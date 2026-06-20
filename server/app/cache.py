import sqlite3, json, time
from typing import Optional

class Cache:
    def __init__(self, path="cache.sqlite"):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, created_at REAL)""")
        self.conn.commit()

    def get(self, key) -> Optional[dict]:
        c = self.conn.cursor()
        r = c.execute("SELECT value FROM cache WHERE key=?", (key,)).fetchone()
        if not r:
            return None
        return json.loads(r[0])

    def set(self, key, value):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO cache (key,value,created_at) VALUES (?,?,?)", (key, json.dumps(value), time.time()))
        self.conn.commit()
