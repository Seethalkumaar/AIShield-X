from monitor import start_monitor
import os

if __name__ == "__main__":
    folder = "test_folder"

    if not os.path.exists(folder):
        os.makedirs(folder)

    start_monitor(folder)