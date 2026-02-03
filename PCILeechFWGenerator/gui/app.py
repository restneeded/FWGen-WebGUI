#!/usr/bin/env python3
"""
PCILeech Firmware Generator - Web GUI

A clean, simple web interface for donor device cloning.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from flask import Flask, jsonify, render_template, request, Response

app = Flask(__name__)
app.secret_key = os.urandom(24)

PROJECT_ROOT = Path(__file__).parent.parent
BUILD_STATUS: Dict[str, Any] = {
    "running": False,
    "progress": 0,
    "stage": "",
    "log": [],
    "error": None,
    "output_file": None,
}
BUILD_LOCK = threading.Lock()


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
    
    try:
        with open("/sys/kernel/iommu_groups/0/devices", "r") as f:
            status.iommu_enabled = True
    except (FileNotFoundError, PermissionError):
        iommu_groups = Path("/sys/kernel/iommu_groups")
        if iommu_groups.exists():
            status.iommu_enabled = any(iommu_groups.iterdir())
    
    try:
        result = subprocess.run(
            ["lsmod"], capture_output=True, text=True, timeout=5
        )
        status.vfio_loaded = "vfio_pci" in result.stdout
    except Exception:
        pass
    
    return status


def get_pci_devices() -> List[Dict[str, str]]:
    """Get list of PCI devices suitable for cloning."""
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
                    skip_classes = ["0600", "0601", "0604", "0605", "0780"]
                    if class_code not in skip_classes:
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


def get_available_boards() -> List[Dict[str, str]]:
    """Get list of supported boards."""
    return [
        {"id": "pcileech_enigma_x1", "name": "Enigma X1", "description": "LambdaConcept Enigma X1"},
        {"id": "pcileech_squirrel", "name": "Squirrel", "description": "LambdaConcept Squirrel"},
        {"id": "pcileech_screamer", "name": "Screamer", "description": "LambdaConcept Screamer"},
        {"id": "pcileech_35t325_x1", "name": "35T325 X1", "description": "Artix-7 35T/325T Board"},
        {"id": "pcileech_75t484", "name": "75T484", "description": "Artix-7 75T Board"},
    ]


BOARD_DIRS = {
    "pcileech_enigma_x1": "EnigmaX1",
    "pcileech_squirrel": "Squirrel",
    "pcileech_screamer": "Screamer",
    "pcileech_35t325_x1": "35T325",
    "pcileech_75t484": "75T484",
}


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
            container_flag,
            "--verbose"
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
        for line in iter(process.stdout.readline, ""):
            line = line.strip()
            if line:
                update_status("Building", min(progress, 90), line)
                if "collect" in line.lower():
                    progress = 30
                elif "template" in line.lower() or "generat" in line.lower():
                    progress = 50
                elif "vivado" in line.lower():
                    progress = 70
                elif "complete" in line.lower() or "success" in line.lower():
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
            update_status("Failed", 0, BUILD_STATUS["error"])
    
    except Exception as e:
        BUILD_STATUS["error"] = str(e)
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
