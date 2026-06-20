import sqlite3, json, time, os
from typing import Optional

class Cache:
    def __init__(self, path="cache.sqlite", default_ttl: Optional[int] = None):
        self.conn = sqlite3.connect(path, check_same_thread=False)
        # default TTL in seconds
        env_ttl = os.getenv("BURP_THINKER_CACHE_TTL")
        if default_ttl is None:
            try:
                default_ttl = int(env_ttl) if env_ttl else 3600
            except Exception:
                default_ttl = 3600
        self.default_ttl = default_ttl
        self._init()

    def _init(self):
        c = self.conn.cursor()
        # keep schema compatible with older versions (key, value, created_at)
        c.execute("""CREATE TABLE IF NOT EXISTS cache (key TEXT PRIMARY KEY, value TEXT, created_at REAL)""")
        self.conn.commit()

    def get(self, key) -> Optional[dict]:
        c = self.conn.cursor()
        r = c.execute("SELECT value, created_at FROM cache WHERE key=?", (key,)).fetchone()
        if not r:
            return None
        value_text, created_at = r
        try:
            created_at = float(created_at)
        except Exception:
            created_at = time.time()
        # TTL enforcement
        age = time.time() - created_at
        if age > self.default_ttl:
            # entry expired: delete and return None
            try:
                c.execute("DELETE FROM cache WHERE key=?", (key,))
                self.conn.commit()
            except Exception:
                pass
            return None
        try:
            return json.loads(value_text)
        except Exception:
            return None

    def set(self, key, value, ttl: Optional[int] = None):
        c = self.conn.cursor()
        c.execute("INSERT OR REPLACE INTO cache (key,value,created_at) VALUES (?,?,?)", (key, json.dumps(value), time.time()))
        self.conn.commit()
