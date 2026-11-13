import subprocess


def system_uptime() -> str:
    return subprocess.check_output("uptime -p", shell=True, text=True).strip()


def disk_usage() -> str:
    return subprocess.check_output("df -h /", shell=True, text=True)
