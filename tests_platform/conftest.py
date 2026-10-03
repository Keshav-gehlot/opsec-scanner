import os

# Tests drive monitoring scans explicitly; no background scheduler thread.
os.environ.setdefault("PLATFORM_SCHEDULER_ENABLED", "false")
