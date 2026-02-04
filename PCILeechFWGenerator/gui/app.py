#!/usr/bin/env python3
"""
PCILeech Firmware Generator - Web GUI

A clean, simple web interface for donor device cloning.
"""

import json
import logging
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, Response

app = Flask(__name__)
app.secret_key = os.urandom(24)

PROJECT_ROOT = Path(__file__).parent.parent
CONFIG_FILE = PROJECT_ROOT / "gui" / "config.json"
ERROR_LOG_FILE = PROJECT_ROOT / "gui" / "error.log"

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s | %(levelname)-7s | %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)
logger = logging.getLogger("pcileech_gui")
logger.setLevel(logging.DEBUG)

ERROR_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
file_handler = logging.FileHandler(ERROR_LOG_FILE, mode='a')
file_handler.setLevel(logging.WARNING)
file_handler.setFormatter(logging.Formatter('%(asctime)s | %(levelname)-7s | %(message)s'))
logger.addHandler(file_handler)
logger.propagate = True


def log_error(message: str, exception: Exception = None):
    """Log error to file and console."""
    if exception:
        logger.error(f"{message}: {exception}")
    else:
        logger.error(message)


def log_warning(message: str):
    """Log warning to file and console."""
    logger.warning(message)

BUILD_STATUS: Dict[str, Any] = {
    "running": False,
    "progress": 0,
    "stage": "",
    "log": [],
    "error": None,
    "output_file": None,
    "error_lines": [],
}
BUILD_LOCK = threading.Lock()

CONSOLE_ERROR_LOG: List[str] = []


def load_config() -> Dict[str, Any]:
    """Load configuration from file."""
    default_config = {
        "vivado_path": "",
    }
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE) as f:
                saved = json.load(f)
                default_config.update(saved)
        except Exception:
            pass
    return default_config


def save_config(config: Dict[str, Any]) -> None:
    """Save configuration to file."""
    with open(CONFIG_FILE, "w") as f:
        json.dump(config, f, indent=2)


@dataclass
class SystemStatus:
    """System requirements status."""
    podman_available: bool = False
    docker_available: bool = False
    iommu_enabled: bool = False
    vfio_loaded: bool = False
    is_root: bool = False
    
    @property
    def container_runtime(self) -> Optional[str]:
        if self.podman_available:
            return "podman"
        if self.docker_available:
            return "docker"
        return None
    
    @property
    def ready_for_full_capture(self) -> bool:
        return (self.container_runtime is not None and 
                self.iommu_enabled and 
                self.vfio_loaded and
                self.is_root)


def check_system_status() -> SystemStatus:
    """Check system requirements."""
    status = SystemStatus()
    
    status.podman_available = shutil.which("podman") is not None
    status.docker_available = shutil.which("docker") is not None
    status.is_root = os.geteuid() == 0
    
    iommu_groups = Path("/sys/kernel/iommu_groups")
    if iommu_groups.exists() and iommu_groups.is_dir():
        try:
            status.iommu_enabled = any(iommu_groups.iterdir())
        except PermissionError:
            status.iommu_enabled = False
    
    try:
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=5
        )
        status.vfio_loaded = "vfio_pci" in result.stdout
    except Exception:
        pass
    
    return status


def is_vfio_bound(bdf: str) -> bool:
    """Check if a PCI device is bound to vfio-pci driver."""
    driver_path = Path(f"/sys/bus/pci/devices/{bdf}/driver")
    if driver_path.is_symlink():
        driver_name = os.path.basename(os.readlink(str(driver_path)))
        return driver_name == "vfio-pci"
    return False


def get_pci_devices() -> List[Dict[str, str]]:
    """Get list of PCI devices bound to VFIO driver."""
    devices = []
    try:
        result = subprocess.run(
            ["lspci", "-nn", "-D"],
            capture_output=True,
            text=True,
            timeout=10
        )
        if result.returncode == 0:
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                match = re.match(
                    r"^(\S+)\s+(.+?)\s+\[([0-9a-fA-F]{4})\]:\s+(.+?)\s+\[([0-9a-fA-F]{4}):([0-9a-fA-F]{4})\]",
                    line
                )
                if match:
                    bdf, dev_class, class_code, name, vendor_id, device_id = match.groups()
                    if is_vfio_bound(bdf):
                        devices.append({
                            "bdf": bdf,
                            "name": name[:60] + "..." if len(name) > 60 else name,
                            "class": dev_class,
                            "class_code": class_code,
                            "vendor_id": vendor_id,
                            "device_id": device_id,
                            "display": f"{bdf} - {name[:50]}"
                        })
    except Exception as e:
        print(f"Error getting PCI devices: {e}")
    
    return devices


BOARD_DIRS = {
    "pcileech_enigma_x1": "EnigmaX1",
    "pcileech_squirrel": "PCIeSquirrel",
    "pcileech_pciescreamer_xc7a35": "pciescreamer",
    "pcileech_screamer_m2": "ScreamerM2",
    "pcileech_ac701": "ac701_ft601",
    "pcileech_100t484_x1": "CaptainDMA/100t484_x1",
    "pcileech_100t484_x4": "CaptainDMA/100t484_x4",
    "pcileech_35t325_x1": "CaptainDMA/35t325_x1",
    "pcileech_35t325_x4": "CaptainDMA/35t325_x4",
    "pcileech_35t484_x1": "CaptainDMA/35t484_x1",
    "pcileech_75t484_x1": "CaptainDMA/75t484_x1",
    "pcileech_gbox": "GBOX",
    "pcileech_netv2_100t": "NeTV2",
    "pcileech_netv2_35t": "NeTV2",
}


def get_available_boards() -> List[Dict[str, str]]:
    """Get list of supported boards from lib folder."""
    boards = [
        {"id": "pcileech_enigma_x1", "name": "Enigma X1", "description": "LambdaConcept Enigma X1"},
        {"id": "pcileech_squirrel", "name": "PCIe Squirrel", "description": "LambdaConcept PCIe Squirrel"},
        {"id": "pcileech_pciescreamer_xc7a35", "name": "PCIe Screamer", "description": "LambdaConcept PCIe Screamer"},
        {"id": "pcileech_screamer_m2", "name": "Screamer M2", "description": "LambdaConcept Screamer M.2"},
        {"id": "pcileech_ac701", "name": "AC701", "description": "Xilinx AC701"},
        {"id": "pcileech_100t484_x1", "name": "100T484 x1", "description": "CaptainDMA/Generic 100T484 x1 lane"},
        {"id": "pcileech_100t484_x4", "name": "100T484 x4", "description": "CaptainDMA/Generic 100T484 x4 lane"},
        {"id": "pcileech_35t325_x1", "name": "35T325 x1", "description": "CaptainDMA/Generic 35T325 x1 lane"},
        {"id": "pcileech_35t325_x4", "name": "35T325 x4", "description": "CaptainDMA/Generic 35T325 x4 lane"},
        {"id": "pcileech_35t484_x1", "name": "35T484 x1", "description": "CaptainDMA/Generic 35T484 x1 lane"},
        {"id": "pcileech_75t484_x1", "name": "75T484 x1", "description": "CaptainDMA/Generic 75T484 x1 lane"},
        {"id": "pcileech_gbox", "name": "GBOX", "description": "GBOX Board"},
        {"id": "pcileech_netv2_100t", "name": "NeTV2 100T", "description": "Kosagi NeTV2 100T"},
        {"id": "pcileech_netv2_35t", "name": "NeTV2 35T", "description": "Kosagi NeTV2 35T"},
    ]
    return boards


def run_build(bdf: str, board: str, output_dir: str):
    """Run the build process in a background thread."""
    global BUILD_STATUS
    
    def update_status(stage: str, progress: int, msg: str = ""):
        BUILD_STATUS["stage"] = stage
        BUILD_STATUS["progress"] = progress
        if msg:
            BUILD_STATUS["log"].append(msg)
            if len(BUILD_STATUS["log"]) > 100:
                BUILD_STATUS["log"] = BUILD_STATUS["log"][-100:]
    
    try:
        update_status("Preparing", 5, f"Starting build for device {bdf}")
        
        status = check_system_status()
        
        errors = []
        if not status.container_runtime:
            errors.append("Container runtime (podman or docker) required")
        if not status.iommu_enabled:
            errors.append("IOMMU must be enabled in BIOS")
        if not status.is_root:
            errors.append("Root access required (run with sudo)")
        if not status.vfio_loaded:
            errors.append("VFIO driver not loaded (modprobe vfio-pci)")
        
        if errors:
            BUILD_STATUS["error"] = f"VFIO+MMIO requirements not met: {'; '.join(errors)}"
            log_error(f"Build failed for {bdf}: {BUILD_STATUS['error']}")
            update_status("Failed", 0, BUILD_STATUS["error"])
            BUILD_STATUS["running"] = False
            return
        
        container_flag = "--container-mode=container"
        update_status("Preparing", 10, f"Using {status.container_runtime} for full VFIO+MMIO capture")
        
        update_status("Collecting", 15, "Collecting device configuration...")
        
        cmd = [
            sys.executable, str(PROJECT_ROOT / "pcileech.py"), "build",
            "--bdf", bdf,
            "--board", board,
            "--build-dir", output_dir,
            container_flag
        ]
        
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            cwd=str(PROJECT_ROOT),
            bufsize=1
        )
        
        progress = 20
        global CONSOLE_ERROR_LOG
        for line in iter(process.stdout.readline, ""):
            line = line.strip()
            if line:
                update_status("Building", min(progress, 90), line)
                
                line_lower = line.lower()
                is_error = 'error' in line_lower or 'fail' in line_lower
                
                if is_error:
                    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                    CONSOLE_ERROR_LOG.append(f"{timestamp} | {line}")
                    if len(CONSOLE_ERROR_LOG) > 500:
                        CONSOLE_ERROR_LOG = CONSOLE_ERROR_LOG[-500:]
                    log_error(f"[BUILD] {line}")
                
                if "collect" in line_lower:
                    progress = 30
                elif "template" in line_lower or "generat" in line_lower:
                    progress = 50
                elif "vivado" in line_lower:
                    progress = 70
                elif "complete" in line_lower or "success" in line_lower:
                    progress = 95
                else:
                    progress = min(progress + 1, 90)
        
        process.wait()
        
        if process.returncode == 0:
            board_dir = BOARD_DIRS.get(board, "EnigmaX1")
            bin_name = f"{board}.bin"
            
            bin_file = Path(output_dir) / bin_name
            board_bin = PROJECT_ROOT / "lib" / "voltcyclone-fpga" / board_dir / bin_name
            output_bin = Path(output_dir) / "pcileech_cfgspace.coe"
            
            if bin_file.exists():
                BUILD_STATUS["output_file"] = str(bin_file)
            elif board_bin.exists():
                BUILD_STATUS["output_file"] = str(board_bin)
            elif output_bin.exists():
                BUILD_STATUS["output_file"] = str(Path(output_dir).absolute())
            else:
                BUILD_STATUS["output_file"] = str(Path(output_dir).absolute())
            
            update_status("Complete", 100, "Build completed successfully!")
        else:
            BUILD_STATUS["error"] = f"Build failed with exit code {process.returncode}"
            log_error(f"Build failed for {bdf} on {board}: exit code {process.returncode}")
            for log_line in BUILD_STATUS["log"][-20:]:
                if "error" in log_line.lower() or "fail" in log_line.lower():
                    log_error(f"  {log_line}")
            update_status("Failed", 0, BUILD_STATUS["error"])
    
    except Exception as e:
        BUILD_STATUS["error"] = str(e)
        log_error(f"Build exception for {bdf} on {board}", e)
        update_status("Failed", 0, f"Error: {e}")
    
    finally:
        BUILD_STATUS["running"] = False


@app.route("/")
def index():
    """Main page."""
    return render_template("index.html")


@app.route("/api/status")
def api_status():
    """Get system status."""
    status = check_system_status()
    return jsonify({
        "podman": status.podman_available,
        "docker": status.docker_available,
        "container_runtime": status.container_runtime,
        "iommu": status.iommu_enabled,
        "vfio": status.vfio_loaded,
        "root": status.is_root,
        "ready": status.ready_for_full_capture,
    })


@app.route("/api/devices")
def api_devices():
    """Get list of PCI devices."""
    return jsonify(get_pci_devices())


@app.route("/api/boards")
def api_boards():
    """Get list of supported boards."""
    return jsonify(get_available_boards())


@app.route("/api/build", methods=["POST"])
def api_build():
    """Start a build."""
    global BUILD_STATUS
    
    with BUILD_LOCK:
        if BUILD_STATUS["running"]:
            return jsonify({"error": "Build already in progress"}), 400
        
        data = request.json
        bdf = data.get("bdf")
        board = data.get("board")
        output_dir = data.get("output_dir", "./output")
        
        if not bdf or not board:
            return jsonify({"error": "Missing bdf or board"}), 400
        
        BUILD_STATUS = {
            "running": True,
            "progress": 0,
            "stage": "Starting",
            "log": [],
            "error": None,
            "output_file": None,
        }
        
        thread = threading.Thread(
            target=run_build,
            args=(bdf, board, output_dir),
            daemon=True
        )
        thread.start()
        
        return jsonify({"status": "started"})


@app.route("/api/build/status")
def api_build_status():
    """Get current build status."""
    return jsonify(BUILD_STATUS)


@app.route("/api/build/cancel", methods=["POST"])
def api_build_cancel():
    """Cancel current build (not fully implemented - builds should complete)."""
    return jsonify({"status": "cannot cancel - let build complete"})


@app.route("/api/settings")
def api_get_settings():
    """Get current settings."""
    config = load_config()
    vivado_path = config.get("vivado_path", "")
    vivado_valid = False
    vivado_version = ""
    
    if vivado_path:
        settings_path = Path(vivado_path) / "settings64.sh"
        if settings_path.exists():
            vivado_valid = True
            version_match = re.search(r"Vivado[/\\](\d+\.\d+)", vivado_path)
            if version_match:
                vivado_version = version_match.group(1)
    
    return jsonify({
        "vivado_path": vivado_path,
        "vivado_valid": vivado_valid,
        "vivado_version": vivado_version,
    })


@app.route("/api/settings", methods=["POST"])
def api_save_settings():
    """Save settings."""
    data = request.json
    config = load_config()
    
    if "vivado_path" in data:
        vivado_path = data["vivado_path"].strip()
        if vivado_path:
            settings_path = Path(vivado_path) / "settings64.sh"
            if not settings_path.exists():
                return jsonify({
                    "error": f"Invalid Vivado path: settings64.sh not found in {vivado_path}"
                }), 400
        config["vivado_path"] = vivado_path
    
    save_config(config)
    return jsonify({"status": "saved"})


@app.route("/api/cleanup", methods=["POST"])
def api_cleanup():
    """Clean up build artifacts and temporary files."""
    cleaned = []
    errors = []
    
    cleanup_dirs = [
        PROJECT_ROOT / "output",
        PROJECT_ROOT / ".cache",
        PROJECT_ROOT / "__pycache__",
        PROJECT_ROOT / "src" / "__pycache__",
    ]
    
    for d in cleanup_dirs:
        if d.exists() and d.is_dir():
            try:
                for item in d.iterdir():
                    if item.is_file():
                        item.unlink()
                    elif item.is_dir():
                        shutil.rmtree(item)
                cleaned.append(str(d.relative_to(PROJECT_ROOT)))
            except Exception as e:
                errors.append(f"{d.name}: {e}")
    
    cleanup_patterns = ["*.pyc", "*.pyo", "*.log"]
    for pattern in cleanup_patterns:
        for f in PROJECT_ROOT.rglob(pattern):
            if ".git" not in str(f) and "venv" not in str(f):
                try:
                    f.unlink()
                    cleaned.append(str(f.relative_to(PROJECT_ROOT)))
                except Exception:
                    pass
    
    runtime = None
    for cmd in ["podman", "docker"]:
        if shutil.which(cmd):
            runtime = cmd
            break
    
    if runtime:
        try:
            result = subprocess.run(
                [runtime, "image", "ls", "-q", "--filter", "reference=*pcileech*"],
                capture_output=True, text=True, timeout=30
            )
            if result.stdout.strip():
                images = result.stdout.strip().split('\n')
                for img in images[:5]:
                    subprocess.run([runtime, "rmi", "-f", img], capture_output=True, timeout=60)
                cleaned.append(f"Removed {len(images)} container image(s)")
        except Exception as e:
            errors.append(f"Container cleanup: {e}")
    
    msg_parts = []
    if cleaned:
        msg_parts.append(f"Cleaned: {len(cleaned)} items")
    if errors:
        msg_parts.append(f"Errors: {len(errors)}")
    
    return jsonify({
        "status": "ok",
        "message": " | ".join(msg_parts) if msg_parts else "Nothing to clean",
        "cleaned": cleaned[:20],
        "errors": errors
    })


@app.route("/api/error-log")
def api_error_log():
    """Get error log contents - returns red console lines."""
    global CONSOLE_ERROR_LOG
    if CONSOLE_ERROR_LOG:
        return jsonify({"log": "\n".join(CONSOLE_ERROR_LOG[-100:])})
    return jsonify({"log": "(No errors captured yet)"})


@app.route("/api/error-log/clear", methods=["POST"])
def api_clear_error_log():
    """Clear the error log."""
    global CONSOLE_ERROR_LOG
    CONSOLE_ERROR_LOG = []
    return jsonify({"status": "cleared"})


if __name__ == "__main__":
    print("=" * 60)
    print(" PCILeech Firmware Generator - Web GUI")
    print("=" * 60)
    print()
    print(" Open http://localhost:5000 in your browser")
    print()
    print(" NOTE: Run with sudo for full VFIO access")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
