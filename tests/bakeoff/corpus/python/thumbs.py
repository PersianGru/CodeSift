import shlex
import subprocess


def make_thumbnail(path: str) -> None:
    command = "convert " + shlex.quote(path) + " -resize 64x64 /tmp/thumb.png"
    subprocess.run(command, shell=True, check=True)
