#!/usr/bin/env python3
import time
import os
import json
import logging as _logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import subprocess


WATCH_FOLDER = "/home/defender/Desktop/new_detection"
LOG_FILE = os.path.join(WATCH_FOLDER, "alerts.log")


_logging.basicConfig(
    level=_logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s"
)


class JSONFileHandler(FileSystemEventHandler):
    def on_created(self, event):
        
        if not event.is_directory and event.src_path.endswith(".json"):
            json_file = event.src_path
            print(f"\n[+] New JSON file detected: {json_file}")


            print("Running smart detection...")


            cmd = [
                "python3",
                os.path.join(WATCH_FOLDER, "new.py"),
                json_file,
                "--log",
                LOG_FILE
            ]

            try:
                subprocess.run(cmd, check=True)
            except subprocess.CalledProcessError as e:
                _logging.error(f"Detection script failed for {json_file}: {e}")
            except Exception as e:
                _logging.error(f"Unexpected error while running detection: {e}")
            else:
                print(f"[+] Detection completed for {os.path.basename(json_file)}\n")


if __name__ == "__main__":
    print(f"[!!!]  Watching folder: {WATCH_FOLDER}\n")

    event_handler = JSONFileHandler()
    observer = Observer()
    observer.schedule(event_handler, WATCH_FOLDER, recursive=False)
    observer.start()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

