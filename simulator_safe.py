import os
import time
import random
from pathlib import Path

def simulate_attack():
    folder = Path("sandbox")
    folder.mkdir(exist_ok=True)

    files = []

    # create files
    for i in range(10):
        file = folder / f"file_{i}.txt"
        file.write_text("normal data")
        files.append(file)

    time.sleep(1)

    # simulate ransomware behavior
    for f in files:
        try:
            # overwrite with random data (entropy ↑)
            f.write_bytes(os.urandom(5000))

            # rename file
            new_name = f.with_suffix(".locked")
            f.rename(new_name)

            time.sleep(0.2)

        except Exception as e:
            print("Simulation error:", e)