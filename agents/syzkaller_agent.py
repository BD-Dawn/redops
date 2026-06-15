"""Syzkaller integration — kernel syscall fuzzing via QEMU VMs.

Manages syzkaller instances for targeted kernel subsystem fuzzing:
  1. Build kernel with KASAN/KMSAN/KCSAN instrumentation
  2. Generate syzkaller config targeting specific subsystems
  3. Launch syz-manager with QEMU backend
  4. Monitor for crashes, feed into triage pipeline
  5. Auto-stop at crash threshold

Subsystem targeting uses syscall groups:
  - filesystem: mount, open, read, write, ioctl on specific fs types
  - network: socket, bind, connect, sendmsg, recvmsg with protocol filters
  - io_uring: io_uring_setup, io_uring_enter, io_uring_register
  - memory: mmap, mremap, mprotect, copy_file_range, splice
  - ipc: pipe, msgget, semget, shmget, futex
"""

import json
import os
import re
import shutil
import subprocess
import time
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import DATA_DIR
from research_engagement import ResearchEngagement


# --- Configuration ---

SYZKALLER_DIR = Path(os.getenv("SYZKALLER_DIR", "/opt/syzkaller"))
CRASH_THRESHOLD = 5
FUZZ_MAX_DURATION = 7200  # 2 hours for kernel fuzzing (longer than userspace)
QEMU_CPU_COUNT = 2
QEMU_MEM_MB = 2048
VM_COUNT = 2  # parallel VMs


# Syscall groups for subsystem targeting
_SUBSYSTEM_SYSCALLS = {
    "filesystem": [
        "open", "openat", "read", "write", "close", "stat", "fstat", "lstat",
        "mount", "umount2", "ioctl", "readdir", "getdents64", "fallocate",
        "copy_file_range", "splice", "sendfile", "fsetxattr", "fgetxattr",
    ],
    "network": [
        "socket", "bind", "listen", "accept", "connect", "sendmsg", "recvmsg",
        "setsockopt", "getsockopt", "sendto", "recvfrom", "shutdown",
    ],
    "io_uring": [
        "io_uring_setup", "io_uring_enter", "io_uring_register",
    ],
    "memory": [
        "mmap", "munmap", "mremap", "mprotect", "madvise", "brk",
        "copy_file_range", "process_vm_readv", "process_vm_writev",
        "userfaultfd", "memfd_create",
    ],
    "ipc": [
        "pipe", "pipe2", "msgget", "msgsnd", "msgrcv", "msgctl",
        "semget", "semop", "semctl", "shmget", "shmat", "shmdt", "shmctl",
        "futex", "eventfd", "signalfd", "timerfd_create",
    ],
    "namespace": [
        "clone", "unshare", "setns", "mount", "pivot_root",
    ],
    "bpf": [
        "bpf",
    ],
    "netfilter": [
        "setsockopt", "getsockopt",  # nf_tables uses these
    ],
    "vsock": [
        "socket", "bind", "connect", "sendmsg", "recvmsg",
    ],
}


def _has_syzkaller() -> bool:
    """Check if syzkaller is installed."""
    return (SYZKALLER_DIR / "bin" / "syz-manager").exists()


def _has_qemu() -> bool:
    try:
        return subprocess.run(
            ["which", "qemu-system-x86_64"], capture_output=True, timeout=5
        ).returncode == 0
    except Exception:
        return False


def install_syzkaller(on_status=None) -> bool:
    """Install syzkaller from source. Requires Go."""
    if _has_syzkaller():
        return True

    if on_status:
        on_status("[syzkaller] Installing syzkaller...")

    # Check Go
    try:
        result = subprocess.run(["go", "version"], capture_output=True, text=True, timeout=5)
        if result.returncode != 0:
            if on_status:
                on_status("[syzkaller] Go not installed. Install with: sudo apt install golang-go")
            return False
    except Exception:
        if on_status:
            on_status("[syzkaller] Go not found")
        return False

    try:
        SYZKALLER_DIR.mkdir(parents=True, exist_ok=True)
        # Clone and build
        subprocess.run(
            ["git", "clone", "--depth", "1",
             "https://github.com/google/syzkaller.git", str(SYZKALLER_DIR)],
            timeout=300, check=True,
        )
        subprocess.run(
            ["make"], cwd=str(SYZKALLER_DIR), timeout=600, check=True,
        )
        if on_status:
            on_status(f"[syzkaller] Installed to {SYZKALLER_DIR}")
        return True
    except Exception as e:
        if on_status:
            on_status(f"[syzkaller] Install failed: {e}")
        return False


# --- Kernel build ---

def build_kernel_instrumented(kernel_src: str, output_dir: str,
                              on_status=None) -> Path | None:
    """Build kernel with KASAN + KCOV instrumentation for syzkaller.

    Returns path to bzImage, or None on failure.
    """
    src = Path(kernel_src)
    out = Path(output_dir)
    out.mkdir(parents=True, exist_ok=True)

    if on_status:
        on_status("[syzkaller] Building instrumented kernel...")

    # Generate config with required options
    config_additions = """
CONFIG_KASAN=y
CONFIG_KASAN_INLINE=y
CONFIG_KCOV=y
CONFIG_KCOV_INSTRUMENT_ALL=y
CONFIG_KCOV_ENABLE_COMPARISONS=y
CONFIG_DEBUG_INFO=y
CONFIG_DEBUG_INFO_DWARF_TOOLCHAIN_DEFAULT=y
CONFIG_CONFIGFS_FS=y
CONFIG_SECURITYFS=y
CONFIG_CMDLINE_BOOL=y
CONFIG_CMDLINE="net.ifnames=0"
CONFIG_FAULT_INJECTION=y
CONFIG_FAULT_INJECTION_DEBUG_FS=y
CONFIG_FAILSLAB=y
CONFIG_FAIL_FUTEX=y
CONFIG_FAIL_IO_TIMEOUT=y
CONFIG_FAIL_MMC_REQUEST=y
CONFIG_FAIL_PAGE_ALLOC=y
"""

    try:
        # Start from defconfig
        subprocess.run(
            ["make", f"O={out}", "defconfig"],
            cwd=str(src), capture_output=True, timeout=60, check=True,
        )

        # Append KASAN/KCOV options
        config_path = out / ".config"
        with open(config_path, "a") as f:
            f.write(config_additions)

        # Resolve config
        subprocess.run(
            ["make", f"O={out}", "olddefconfig"],
            cwd=str(src), capture_output=True, timeout=60, check=True,
        )

        # Build with parallel jobs
        import multiprocessing
        jobs = multiprocessing.cpu_count()
        if on_status:
            on_status(f"[syzkaller] Compiling kernel ({jobs} jobs)...")

        result = subprocess.run(
            ["make", f"O={out}", f"-j{jobs}", "bzImage"],
            cwd=str(src), capture_output=True, text=True, timeout=3600,
        )

        bzimage = out / "arch" / "x86" / "boot" / "bzImage"
        if bzimage.exists():
            if on_status:
                on_status(f"[syzkaller] Kernel built: {bzimage}")
            return bzimage
        else:
            if on_status:
                on_status(f"[syzkaller] Build failed: {result.stderr[-500:]}")
    except Exception as e:
        if on_status:
            on_status(f"[syzkaller] Build error: {e}")

    return None


# --- Disk image ---

def create_disk_image(output_path: str, on_status=None) -> bool:
    """Create a minimal Debian disk image for syzkaller QEMU VMs."""
    if os.path.exists(output_path):
        return True

    if on_status:
        on_status("[syzkaller] Creating QEMU disk image...")

    # Use syzkaller's create-image.sh if available
    script = SYZKALLER_DIR / "tools" / "create-image.sh"
    if script.exists():
        try:
            result = subprocess.run(
                ["bash", str(script)],
                cwd=str(Path(output_path).parent),
                capture_output=True, text=True, timeout=600,
            )
            default_img = Path(output_path).parent / "stretch.img"
            if default_img.exists():
                shutil.move(str(default_img), output_path)
                return True
        except Exception:
            pass

    # Fallback: create minimal image with debootstrap
    try:
        subprocess.run(
            ["qemu-img", "create", "-f", "raw", output_path, "2G"],
            check=True, capture_output=True, timeout=10,
        )
        subprocess.run(
            ["mkfs.ext4", "-F", output_path],
            check=True, capture_output=True, timeout=30,
        )
        if on_status:
            on_status(f"[syzkaller] Disk image created: {output_path}")
        return True
    except Exception as e:
        if on_status:
            on_status(f"[syzkaller] Disk image creation failed: {e}")
    return False


# --- Syzkaller config ---

def generate_syz_config(
    workdir: str,
    kernel_obj: str,
    kernel_src: str,
    disk_image: str,
    ssh_key: str = "",
    subsystems: list[str] = None,
    on_status=None,
) -> Path:
    """Generate syzkaller configuration file.

    Args:
        workdir: syzkaller working directory for this run
        kernel_obj: path to kernel build output (with vmlinux)
        kernel_src: path to kernel source
        disk_image: path to QEMU disk image
        ssh_key: path to SSH key for VM access
        subsystems: list of subsystem names to target (filters syscalls)
    """
    # Build syscall enable list from subsystems
    enable_syscalls = []
    if subsystems:
        for sub in subsystems:
            syscalls = _SUBSYSTEM_SYSCALLS.get(sub, [])
            enable_syscalls.extend(syscalls)
        enable_syscalls = sorted(set(enable_syscalls))

    config = {
        "target": "linux/amd64",
        "http": "127.0.0.1:56741",
        "workdir": workdir,
        "kernel_obj": kernel_obj,
        "kernel_src": kernel_src,
        "image": disk_image,
        "syzkaller": str(SYZKALLER_DIR),
        "procs": 4,
        "type": "qemu",
        "vm": {
            "count": VM_COUNT,
            "cpu": QEMU_CPU_COUNT,
            "mem": QEMU_MEM_MB,
            "kernel": os.path.join(kernel_obj, "arch/x86/boot/bzImage"),
        },
    }

    if ssh_key:
        config["sshkey"] = ssh_key
    if enable_syscalls:
        config["enable_syscalls"] = enable_syscalls

    config_path = Path(workdir) / "syz.cfg"
    Path(workdir).mkdir(parents=True, exist_ok=True)
    config_path.write_text(json.dumps(config, indent=2))

    if on_status:
        targeted = f", targeting: {', '.join(subsystems)}" if subsystems else ""
        on_status(f"[syzkaller] Config generated: {VM_COUNT} VMs, {QEMU_CPU_COUNT} CPUs each{targeted}")

    return config_path


# --- Launch and monitor ---

def launch_syzkaller(config_path: Path, on_status=None) -> subprocess.Popen | None:
    """Launch syz-manager in background. Returns the process."""
    syz_manager = SYZKALLER_DIR / "bin" / "syz-manager"
    if not syz_manager.exists():
        if on_status:
            on_status("[syzkaller] syz-manager not found — install syzkaller first")
        return None

    if on_status:
        on_status("[syzkaller] Launching syz-manager...")

    try:
        proc = subprocess.Popen(
            [str(syz_manager), f"-config={config_path}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if on_status:
            on_status(f"[syzkaller] syz-manager started (PID {proc.pid})")
        return proc
    except Exception as e:
        if on_status:
            on_status(f"[syzkaller] Launch failed: {e}")
        return None


def collect_crashes(workdir: str) -> list[dict]:
    """Collect crash reports from syzkaller workdir.

    Syzkaller stores crashes in workdir/crashes/<hash>/
    Each crash dir contains: description, log0, report0, repro.prog, repro.cprog
    """
    crashes_dir = Path(workdir) / "crashes"
    if not crashes_dir.exists():
        return []

    results = []
    for crash_dir in sorted(crashes_dir.iterdir()):
        if not crash_dir.is_dir():
            continue

        crash = {
            "id": crash_dir.name[:16],
            "crash_type": "",
            "description": "",
            "log": "",
            "report": "",
            "reproducer_prog": "",
            "reproducer_c": "",
            "stack_hash": crash_dir.name[:16],
        }

        # Read description
        desc_file = crash_dir / "description"
        if desc_file.exists():
            crash["description"] = desc_file.read_text().strip()
            crash["crash_type"] = crash["description"].split(" in ")[0] if " in " in crash["description"] else crash["description"][:50]

        # Read report
        for report in sorted(crash_dir.glob("report*")):
            crash["report"] = report.read_text(errors="ignore")[:3000]
            break

        # Read log
        for log in sorted(crash_dir.glob("log*")):
            crash["log"] = log.read_text(errors="ignore")[:2000]
            break

        # Read reproducer
        repro_prog = crash_dir / "repro.prog"
        if repro_prog.exists():
            crash["reproducer_prog"] = repro_prog.read_text()

        repro_c = crash_dir / "repro.cprog"
        if repro_c.exists():
            crash["reproducer_c"] = repro_c.read_text()

        results.append(crash)

    return results


def monitor_syzkaller(proc: subprocess.Popen, workdir: str,
                      engagement: ResearchEngagement,
                      on_status=None) -> dict:
    """Monitor syzkaller until crash threshold or timeout.

    Returns summary dict.
    """
    start_time = time.monotonic()
    known_crashes = set()
    summary = {"crashes": 0, "duration": 0, "reproducers": 0}

    while True:
        elapsed = time.monotonic() - start_time
        if elapsed > FUZZ_MAX_DURATION:
            if on_status:
                on_status(f"[syzkaller] Timeout ({FUZZ_MAX_DURATION}s)")
            break

        # Check if syz-manager is still running
        if proc.poll() is not None:
            if on_status:
                on_status("[syzkaller] syz-manager exited")
            break

        # Collect new crashes
        crashes = collect_crashes(workdir)
        new_crashes = [c for c in crashes if c["id"] not in known_crashes]

        for crash in new_crashes:
            known_crashes.add(crash["id"])
            summary["crashes"] += 1
            if crash.get("reproducer_c") or crash.get("reproducer_prog"):
                summary["reproducers"] += 1

            # Add to engagement
            engagement.add_crash(
                input_file=crash.get("reproducer_c", crash.get("reproducer_prog", "")),
                crash_type=crash.get("crash_type", "unknown"),
                stack_hash=crash["id"],
                stack_trace=crash.get("report", "")[:1000],
                exploitability="",  # triage later
                root_cause=crash.get("description", ""),
            )

            if on_status:
                has_repro = " [REPRODUCER]" if crash.get("reproducer_c") else ""
                on_status(f"[syzkaller] CRASH #{summary['crashes']}: "
                          f"{crash.get('description', '?')[:80]}{has_repro}")

        if summary["crashes"] >= CRASH_THRESHOLD:
            if on_status:
                on_status(f"[syzkaller] Crash threshold ({CRASH_THRESHOLD}) reached")
            break

        # Progress
        if on_status and int(elapsed) % 60 == 0 and elapsed > 0:
            on_status(f"[syzkaller] {int(elapsed)}s | crashes: {summary['crashes']}/{CRASH_THRESHOLD} | "
                      f"reproducers: {summary['reproducers']}")

        time.sleep(30)

    # Cleanup
    proc.terminate()
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()

    summary["duration"] = time.monotonic() - start_time
    engagement.save()

    if on_status:
        on_status(f"[syzkaller] Complete: {summary['crashes']} crashes, "
                  f"{summary['reproducers']} reproducers in {summary['duration']:.0f}s")
    return summary


# --- High-level pipeline ---

def run_syzkaller(engagement: ResearchEngagement, kernel_src: str,
                  subsystems: list[str] = None, on_status=None) -> dict:
    """Run full syzkaller pipeline.

    1. Check/install syzkaller
    2. Build instrumented kernel
    3. Create disk image
    4. Generate config
    5. Launch and monitor

    Args:
        engagement: Research engagement state
        kernel_src: Path to kernel source tree
        subsystems: List of subsystem names to target (e.g., ["io_uring", "memory"])
    """
    if not _has_qemu():
        if on_status:
            on_status("[syzkaller] QEMU not available")
        return {"error": "QEMU not installed"}

    if not _has_syzkaller():
        if on_status:
            on_status("[syzkaller] Syzkaller not installed — attempting install...")
        if not install_syzkaller(on_status):
            return {"error": "Syzkaller installation failed — install Go and retry"}

    workdir = str(engagement.fuzz_dir / "syzkaller")
    kernel_build = str(engagement.fuzz_dir / "kernel_build")

    # Step 1: Build instrumented kernel
    bzimage = build_kernel_instrumented(kernel_src, kernel_build, on_status)
    if not bzimage:
        return {"error": "Kernel build failed"}

    # Step 2: Create disk image
    image_path = str(engagement.fuzz_dir / "syzkaller_image.img")
    if not create_disk_image(image_path, on_status):
        return {"error": "Disk image creation failed"}

    # Step 3: Generate config
    config = generate_syz_config(
        workdir=workdir,
        kernel_obj=kernel_build,
        kernel_src=kernel_src,
        disk_image=image_path,
        subsystems=subsystems,
        on_status=on_status,
    )

    # Step 4: Launch
    proc = launch_syzkaller(config, on_status)
    if not proc:
        return {"error": "Syzkaller launch failed"}

    # Step 5: Monitor
    summary = monitor_syzkaller(proc, workdir, engagement, on_status)

    engagement.current_phase = "fuzzing"
    if "fuzzing" not in engagement.completed_phases:
        engagement.completed_phases.append("fuzzing")
    engagement.save()

    return summary
