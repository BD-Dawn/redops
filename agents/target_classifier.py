"""Target classifier agent — identifies what a research target is and recommends an analysis pipeline.

Deterministic first pass (file type detection, language identification, binary analysis),
then LLM assessment of attack surface and recommended agent pipeline.
"""

import json
import os
import re
import subprocess
from pathlib import Path

import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import MODEL_FAST
from research_engagement import TargetProfile


# --- Language detection by file extension ---

_LANG_EXTENSIONS: dict[str, str] = {
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".cxx": "cpp",
    ".hpp": "cpp", ".hxx": "cpp",
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".php": "php", ".phtml": "php",
    ".java": "java", ".kt": "kotlin", ".scala": "scala",
    ".go": "go",
    ".rs": "rust",
    ".rb": "ruby",
    ".cs": "csharp",
    ".swift": "swift",
    ".m": "objc", ".mm": "objc",
    ".lua": "lua",
    ".pl": "perl", ".pm": "perl",
    ".sh": "shell", ".bash": "shell",
    ".asm": "assembly", ".s": "assembly",
}

# Build systems
_BUILD_FILES: dict[str, str] = {
    "Makefile": "make", "makefile": "make", "GNUmakefile": "make",
    "CMakeLists.txt": "cmake",
    "configure": "autotools", "configure.ac": "autotools",
    "meson.build": "meson",
    "package.json": "npm",
    "requirements.txt": "pip", "setup.py": "pip", "pyproject.toml": "pip",
    "Cargo.toml": "cargo",
    "go.mod": "go",
    "pom.xml": "maven", "build.gradle": "gradle",
    "Gemfile": "bundler",
    "composer.json": "composer",
}

# Dangerous C/C++ functions (for binary prioritization)
_DANGEROUS_FUNCTIONS = {
    "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf",
    "memcpy", "memmove", "strncpy",  # safe-ish but often misused
    "system", "popen", "exec", "execve", "execvp",
    "dlopen", "dlsym",
    "malloc", "free", "realloc",  # UAF/double-free potential
    "fopen", "fread", "fwrite",
    "recv", "recvfrom", "read",  # network/file input
}


def _count_lines(path: Path) -> int:
    """Fast LOC estimate using wc -l."""
    try:
        result = subprocess.run(
            ["find", str(path), "-type", "f", "-name", "*.c", "-o",
             "-name", "*.cpp", "-o", "-name", "*.h", "-o",
             "-name", "*.py", "-o", "-name", "*.js", "-o",
             "-name", "*.php", "-o", "-name", "*.java", "-o",
             "-name", "*.go", "-o", "-name", "*.rs"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode != 0:
            return 0
        files = result.stdout.strip().split("\n")
        if not files or files == [""]:
            return 0
        # Count lines of first 500 files max
        files = files[:500]
        result2 = subprocess.run(
            ["wc", "-l"] + files,
            capture_output=True, text=True, timeout=30,
        )
        # Last line of wc output is total
        lines = result2.stdout.strip().split("\n")
        if lines:
            last = lines[-1].strip()
            match = re.match(r"(\d+)", last)
            if match:
                return int(match.group(1))
    except Exception:
        pass
    return 0


def _detect_binary(path: Path) -> dict:
    """Analyze a binary file. Returns {format, arch, has_symbols, dangerous_count}."""
    info = {"format": "", "arch": "", "has_symbols": False, "dangerous_count": 0,
            "is_driver": False}
    try:
        result = subprocess.run(
            ["file", str(path)], capture_output=True, text=True, timeout=5,
        )
        output = result.stdout.lower()
        if "elf" in output:
            info["format"] = "elf"
        elif "pe32" in output or "pe64" in output:
            info["format"] = "pe"
        elif "mach-o" in output:
            info["format"] = "macho"

        # Windows kernel-mode driver: native subsystem PE or a .sys file.
        if info["format"] == "pe" and ("native" in output
                                       or path.suffix.lower() == ".sys"):
            info["is_driver"] = True

        if "x86-64" in output or "x86_64" in output or "amd64" in output:
            info["arch"] = "x86_64"
        elif "x86" in output or "i386" in output or "i686" in output:
            info["arch"] = "x86"
        elif "arm" in output or "aarch64" in output:
            info["arch"] = "arm64" if "aarch64" in output else "arm"
        elif "mips" in output:
            info["arch"] = "mips"

        if "not stripped" in output:
            info["has_symbols"] = True
    except Exception:
        pass

    # Count dangerous functions using strings + grep
    try:
        result = subprocess.run(
            ["strings", str(path)], capture_output=True, text=True, timeout=15,
        )
        found = set()
        for line in result.stdout.split("\n"):
            token = line.strip()
            if token in _DANGEROUS_FUNCTIONS:
                found.add(token)
        info["dangerous_count"] = len(found)
        info["dangerous_functions"] = sorted(found)
    except Exception:
        pass

    return info


def _is_firmware(path: Path) -> bool:
    """Check if a file looks like a firmware image."""
    try:
        result = subprocess.run(
            ["binwalk", "--signature", str(path)],
            capture_output=True, text=True, timeout=15,
        )
        # Firmware images have multiple embedded signatures
        sig_count = len([l for l in result.stdout.split("\n") if l.strip() and not l.startswith("DECIMAL")])
        return sig_count >= 3
    except Exception:
        return False


def classify_target(target_path: str) -> TargetProfile:
    """Classify a target using deterministic analysis.

    Examines file types, languages, build systems, and binary properties.
    Does NOT use LLM — pure file analysis.
    """
    path = Path(target_path).resolve()
    profile = TargetProfile(path=str(path))

    if not path.exists():
        return profile

    # --- Single file ---
    if path.is_file():
        ext = path.suffix.lower()
        if ext in _LANG_EXTENSIONS:
            profile.target_type = "source"
            profile.language = _LANG_EXTENSIONS[ext]
            profile.file_count = 1
            try:
                profile.estimated_loc = len(path.read_text(errors="ignore").split("\n"))
            except Exception:
                pass
        else:
            # Check if binary
            bin_info = _detect_binary(path)
            if bin_info["format"]:
                profile.target_type = "binary"
                profile.binary_format = bin_info["format"]
                profile.arch = bin_info["arch"]
                profile.has_symbols = bin_info["has_symbols"]
                profile.is_driver = bin_info.get("is_driver", False)
                profile.file_count = 1
            elif _is_firmware(path):
                profile.target_type = "firmware"
                profile.file_count = 1
            else:
                profile.target_type = "binary"  # fallback
                profile.file_count = 1

        profile.recommended_pipeline = _recommend_pipeline(profile)
        return profile

    # --- Directory (source tree) ---
    if path.is_dir():
        # Count files by language
        lang_counts: dict[str, int] = {}
        total_files = 0
        for root, dirs, files in os.walk(path):
            # Skip common non-source dirs
            dirs[:] = [d for d in dirs if d not in (
                ".git", "node_modules", "__pycache__", ".venv", "venv",
                "vendor", "third_party", "build", "dist", ".cache",
            )]
            for f in files:
                ext = Path(f).suffix.lower()
                if ext in _LANG_EXTENSIONS:
                    lang = _LANG_EXTENSIONS[ext]
                    lang_counts[lang] = lang_counts.get(lang, 0) + 1
                    total_files += 1

        profile.file_count = total_files
        profile.target_type = "source"

        # Primary language = most files
        if lang_counts:
            profile.language = max(lang_counts, key=lang_counts.get)

        # Detect build system
        for fname, build in _BUILD_FILES.items():
            if (path / fname).exists():
                profile.build_system = build
                break

        # LOC estimate
        profile.estimated_loc = _count_lines(path)

        # Check for embedded binaries (could be firmware or mixed)
        bin_files = list(path.glob("**/*.bin")) + list(path.glob("**/*.fw"))
        if bin_files and total_files < 10:
            profile.target_type = "firmware"

        profile.recommended_pipeline = _recommend_pipeline(profile)
        return profile

    return profile


def _recommend_pipeline(profile: TargetProfile) -> list[str]:
    """Recommend agent pipeline based on target profile."""
    pipeline = []

    if profile.target_type == "source":
        pipeline.append("static_auditor")
        if profile.language in ("c", "cpp"):
            pipeline.append("fuzzer")
            pipeline.append("crash_triager")
        pipeline.append("poc_builder")
        pipeline.append("variant_hunter")

    elif profile.target_type == "binary":
        pipeline.append("re_agent")
        # Kernel drivers can't be exercised by the local file-input fuzzer — their
        # input arrives via IOCTLs on a live Windows target. Static RE + PoC only.
        if not profile.is_driver and profile.arch in ("x86_64", "x86", "arm64", "arm"):
            pipeline.append("fuzzer")
            pipeline.append("crash_triager")
        pipeline.append("poc_builder")
        pipeline.append("variant_hunter")

    elif profile.target_type == "firmware":
        pipeline.append("re_agent")  # extract and analyze binaries
        pipeline.append("static_auditor")  # audit any source/scripts found
        pipeline.append("fuzzer")
        pipeline.append("crash_triager")
        pipeline.append("poc_builder")

    elif profile.target_type == "library":
        pipeline.append("static_auditor")
        pipeline.append("fuzzer")
        pipeline.append("crash_triager")
        pipeline.append("poc_builder")
        pipeline.append("variant_hunter")

    return pipeline


def classify_with_llm(profile: TargetProfile, file_listing: str = "") -> TargetProfile:
    """Enhance classification with LLM analysis of attack surface.

    Takes the deterministic profile and a sample file listing,
    asks the LLM to identify entry points and refine the pipeline.
    """
    prompt = f"""Analyze this software target for vulnerability research.

Target type: {profile.target_type}
Language: {profile.language}
Architecture: {profile.arch}
Build system: {profile.build_system}
File count: {profile.file_count}
LOC: {profile.estimated_loc}

File listing (sample):
{file_listing[:3000]}

Respond in JSON only:
{{
  "entry_points": ["list of main functions/handlers that process external input"],
  "attack_surface": "1-2 sentence description of what accepts untrusted input",
  "recommended_pipeline": ["ordered list of: static_auditor, re_agent, fuzzer, crash_triager, poc_builder, variant_hunter"],
  "priority_files": ["top 5 files most likely to contain vulnerabilities"],
  "notes": "any relevant observations about the target"
}}"""

    try:
        result = subprocess.run(
            ["claude", "-p", "--output-format", "text",
             "--max-turns", "1", "--model", MODEL_FAST],
            input=prompt, capture_output=True, text=True, timeout=60,
        )
        if result.returncode == 0 and result.stdout.strip():
            # Extract JSON from response
            text = result.stdout.strip()
            # Find JSON block
            json_match = re.search(r"\{[\s\S]*\}", text)
            if json_match:
                data = json.loads(json_match.group())
                if data.get("entry_points"):
                    profile.entry_points = data["entry_points"]
                if data.get("recommended_pipeline"):
                    profile.recommended_pipeline = data["recommended_pipeline"]
    except Exception:
        pass

    return profile
