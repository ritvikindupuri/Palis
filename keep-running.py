"""Keep the local Palis server running; never change firewall configuration."""
import datetime
import json
import msvcrt
import os
from pathlib import Path
import subprocess
import sys
import time
import urllib.request

ROOT = Path(__file__).resolve().parent

def log(message):
    path = ROOT / 'supervisor.log'
    if path.exists() and path.stat().st_size > 1_000_000:
        path.replace(ROOT / 'supervisor.previous.log')
    with path.open('a', encoding='utf-8') as stream:
        stream.write(datetime.datetime.now(datetime.timezone.utc).isoformat() + ' ' + message + '\n')

def server_available():
    try:
        with urllib.request.urlopen('http://127.0.0.1:8765/api/state', timeout=10) as response:
            state = json.load(response)
            return 'monitor' in state and 'evidence' in state
    except Exception:
        return False

def main():
    # One supervisor per checkout. Windows releases the byte lock on exit.
    lock = (ROOT / 'supervisor.lock').open('a+b')
    lock.seek(0)
    if not lock.read(1):
        lock.write(b'0')
        lock.flush()
    lock.seek(0)
    try:
        msvcrt.locking(lock.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError:
        return
    log('Supervisor started. Collection requires Windows to remain awake.')
    executable = str(Path(sys.executable).with_name('python.exe'))
    while True:
        if server_available():
            time.sleep(20)
            continue
        # Do not compete with an occupied port or terminate an unrelated process.
        import socket
        with socket.socket() as probe:
            if probe.connect_ex(('127.0.0.1', 8765)) == 0:
                log('Port 8765 occupied but Palis health unavailable; waiting.')
                time.sleep(20)
                continue
        for name in ('monitor.stdout.log', 'monitor.stderr.log'):
            path = ROOT / name
            if path.exists() and path.stat().st_size > 2_000_000:
                path.replace(ROOT / (name + '.previous'))
        try:
            with (ROOT / 'monitor.stdout.log').open('ab') as out, (ROOT / 'monitor.stderr.log').open('ab') as err:
                child = subprocess.Popen([executable, str(ROOT / 'server.py')], cwd=ROOT,
                    stdout=out, stderr=err, creationflags=subprocess.CREATE_NO_WINDOW)
                (ROOT / 'monitor.pid').write_text(str(child.pid), encoding='ascii')
                log(f'Started server PID {child.pid}.')
                code = child.wait()
                log(f'Server exited with code {code}; retrying in 20 seconds.')
        except Exception as error:
            log(f'Server launch failed: {error}; retrying in 20 seconds.')
        time.sleep(20)

if __name__ == '__main__':
    main()
