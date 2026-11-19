import os

LOG_FILE_PATH = os.getenv("MODSEC_LOG_PATH", "/var/log/modsec/modsec_audit.log")
DB_FILE_PATH = "waf_logs.db"

