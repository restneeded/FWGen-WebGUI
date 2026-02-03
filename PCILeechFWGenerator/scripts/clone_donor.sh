#!/bin/bash
#
# DONOR CLONING SCRIPT - Fully automated workflow
# 
# Usage: ./scripts/clone_donor.sh <PCI_BDF> [OUTPUT_DIR] [--build]
#
# Examples:
#   ./scripts/clone_donor.sh 0000:03:00.0                    # Capture only
#   ./scripts/clone_donor.sh 0000:03:00.0 /path/to/output    # Capture to specific dir
#   ./scripts/clone_donor.sh 0000:03:00.0 ./output --build   # Capture + Vivado build
#
# This script:
#   1. Captures donor card configuration via VFIO
#   2. Generates device-specific .coe files
#   3. Copies .coe files to EnigmaX1 board IP directory
#   4. Optionally runs Vivado full rebuild (--build flag)
#   5. Copies final .bin to your output directory
#
# For manual Vivado build, run in Vivado Tcl Shell:
#   cd lib/voltcyclone-fpga/EnigmaX1
#   source vivado_full_rebuild.tcl -notrace
#

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

print_header() {
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
    echo -e "${BLUE}  $1${NC}"
    echo -e "${BLUE}═══════════════════════════════════════════════════════════${NC}"
}

print_step() {
    echo -e "${GREEN}[STEP $1]${NC} $2"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

# Check arguments
if [ -z "$1" ]; then
    echo "Usage: $0 <PCI_BDF> [OUTPUT_DIR] [--build]"
    echo ""
    echo "PCI_BDF format: DDDD:BB:DD.F (e.g., 0000:03:00.0)"
    echo ""
    echo "Options:"
    echo "  --build    Run Vivado full rebuild after capture (requires Vivado)"
    echo ""
    echo "Find your donor device BDF with:"
    echo "  lspci -nn"
    echo ""
    exit 1
fi

PCI_BDF="$1"
RUN_BUILD=0
OUTPUT_DIR=""

# Parse arguments
shift
while [ $# -gt 0 ]; do
    case "$1" in
        --build)
            RUN_BUILD=1
            ;;
        *)
            if [ -z "$OUTPUT_DIR" ]; then
                OUTPUT_DIR="$1"
            fi
            ;;
    esac
    shift
done

# Default output dir if not specified
if [ -z "$OUTPUT_DIR" ]; then
    OUTPUT_DIR="./output_$(echo $PCI_BDF | tr ':.' '_')"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BOARD_TYPE="pcileech_enigma_x1"
BOARD_DIR="$PROJECT_ROOT/lib/voltcyclone-fpga/EnigmaX1"

print_header "PCILeech Donor Card Cloning"
echo ""
echo "  Donor BDF:    $PCI_BDF"
echo "  Output Dir:   $OUTPUT_DIR"
echo "  Board Type:   $BOARD_TYPE"
echo "  Board Dir:    $BOARD_DIR"
echo ""

# Step 1: Verify device exists
print_step 1 "Verifying donor device..."
if [ ! -d "/sys/bus/pci/devices/$PCI_BDF" ]; then
    print_error "Device $PCI_BDF not found!"
    echo "Available PCI devices:"
    lspci -nn | head -20
    exit 1
fi

DEVICE_INFO=$(lspci -s "$PCI_BDF" -nn 2>/dev/null || true)
if [ -z "$DEVICE_INFO" ]; then
    print_error "Could not get device info for $PCI_BDF"
    exit 1
fi
echo "  Found: $DEVICE_INFO"

# Step 2: Check for root permissions
print_step 2 "Checking permissions..."
if [ "$EUID" -ne 0 ]; then
    print_warning "Not running as root. VFIO binding may fail."
    echo "  Consider running with: sudo $0 $@"
fi

# Step 3: Check IOMMU is enabled
print_step 3 "Checking IOMMU..."
if [ -d "/sys/class/iommu" ]; then
    IOMMU_GROUPS=$(find /sys/kernel/iommu_groups -maxdepth 1 -type d 2>/dev/null | wc -l)
    if [ "$IOMMU_GROUPS" -gt 1 ]; then
        echo "  IOMMU enabled with $((IOMMU_GROUPS - 1)) groups"
    else
        print_warning "IOMMU may not be properly enabled"
        echo "  Enable in BIOS: VT-d (Intel) or AMD-Vi (AMD)"
    fi
else
    print_warning "Could not verify IOMMU status"
fi

# Step 4: Verify board directory exists
print_step 4 "Verifying board files..."
if [ ! -d "$BOARD_DIR" ]; then
    print_error "Board directory not found: $BOARD_DIR"
    echo "  Make sure lib/voltcyclone-fpga submodule is initialized:"
    echo "  git submodule update --init --recursive"
    exit 1
fi

if [ ! -f "$BOARD_DIR/vivado_full_rebuild.tcl" ]; then
    print_warning "vivado_full_rebuild.tcl not found in board directory"
fi
echo "  Board files OK"

# Step 5: Run Python generator
print_step 5 "Running donor device analysis..."
echo "  This may take a few seconds..."

cd "$PROJECT_ROOT"

# Create output directory
mkdir -p "$OUTPUT_DIR"

# Run the generator
python3 pcileech.py build \
    --bdf "$PCI_BDF" \
    --board "$BOARD_TYPE" \
    --build-dir "$OUTPUT_DIR" \
    --host-collect-only \
    --verbose

if [ $? -ne 0 ]; then
    print_error "Generation failed!"
    exit 1
fi

# Step 6: Verify .coe files were created
print_step 6 "Verifying generated files..."
COE_FILES=("pcileech_cfgspace.coe" "pcileech_cfgspace_writemask.coe")
MISSING_FILES=0

for coe in "${COE_FILES[@]}"; do
    if [ -f "$OUTPUT_DIR/src/$coe" ]; then
        echo "  Created: $coe"
    elif [ -f "$OUTPUT_DIR/ip/$coe" ]; then
        echo "  Created: $coe (in ip/)"
    else
        print_warning "Missing: $coe"
        MISSING_FILES=$((MISSING_FILES + 1))
    fi
done

if [ $MISSING_FILES -gt 0 ]; then
    print_error "Some .coe files were not generated!"
    exit 1
fi

# Step 7: Verify .coe files were copied to board
print_step 7 "Verifying board IP injection..."
if [ -f "$BOARD_DIR/ip/pcileech_cfgspace.coe" ]; then
    # Read first data line to check device IDs
    FIRST_DATA=$(grep -E '^[0-9a-fA-F]{8},' "$BOARD_DIR/ip/pcileech_cfgspace.coe" | head -1)
    if [ -n "$FIRST_DATA" ]; then
        DWORD=$(echo "$FIRST_DATA" | cut -d',' -f1)
        VENDOR_ID="${DWORD:4:4}"
        DEVICE_ID="${DWORD:0:4}"
        echo "  Board IP updated with: Vendor=0x$VENDOR_ID Device=0x$DEVICE_ID"
    fi
else
    print_warning "Board IP .coe file not found - may need manual copy"
fi

# Step 8: Run Vivado build if requested
if [ "$RUN_BUILD" -eq 1 ]; then
    print_step 8 "Running Vivado full rebuild..."
    
    # Find Vivado
    VIVADO_BIN=""
    if command -v vivado &> /dev/null; then
        VIVADO_BIN="vivado"
    elif [ -n "$XILINX_VIVADO" ]; then
        VIVADO_BIN="$XILINX_VIVADO/bin/vivado"
    elif [ -d "/tools/Xilinx" ]; then
        # Find latest Vivado version
        VIVADO_BIN=$(find /tools/Xilinx -name "vivado" -path "*/bin/*" 2>/dev/null | sort -V | tail -1)
    fi
    
    if [ -z "$VIVADO_BIN" ] || [ ! -x "$VIVADO_BIN" ]; then
        print_error "Vivado not found! Cannot run automated build."
        echo ""
        echo "Please install Vivado or set XILINX_VIVADO environment variable."
        echo "Then run manually:"
        echo "  cd $BOARD_DIR"
        echo "  vivado -mode tcl -source vivado_full_rebuild.tcl"
        exit 1
    fi
    
    echo "  Found Vivado: $VIVADO_BIN"
    echo "  Starting build... (this takes 30-60 minutes)"
    echo ""
    
    cd "$BOARD_DIR"
    
    # Run Vivado in batch mode
    "$VIVADO_BIN" -mode batch -source vivado_full_rebuild.tcl -notrace
    BUILD_STATUS=$?
    
    cd "$PROJECT_ROOT"
    
    if [ $BUILD_STATUS -ne 0 ]; then
        print_error "Vivado build failed with exit code $BUILD_STATUS"
        echo "Check the Vivado logs in $BOARD_DIR for details"
        exit 1
    fi
    
    # Copy .bin to output directory
    if [ -f "$BOARD_DIR/pcileech_enigma_x1.bin" ]; then
        cp "$BOARD_DIR/pcileech_enigma_x1.bin" "$OUTPUT_DIR/"
        print_success "Build complete!"
        echo ""
        echo "Your firmware is ready:"
        echo "  $OUTPUT_DIR/pcileech_enigma_x1.bin"
        echo ""
        echo "To flash to your Enigma X1:"
        echo "  cd $BOARD_DIR && vivado -mode tcl -source vivado_flash.tcl"
    else
        print_error ".bin file not found after build!"
        exit 1
    fi
else
    # Capture only - show next steps
    print_header "Donor Capture Complete!"
    echo ""
    print_success "Donor device data captured and .coe files generated"
    echo ""
    echo "Generated files:"
    ls -la "$OUTPUT_DIR/src/"*.coe 2>/dev/null || ls -la "$OUTPUT_DIR/ip/"*.coe 2>/dev/null || echo "  (files in $OUTPUT_DIR)"
    echo ""
    echo -e "${YELLOW}NEXT STEPS:${NC}"
    echo ""
    echo "Option A - Run this script with --build flag:"
    echo "   $0 $PCI_BDF $OUTPUT_DIR --build"
    echo ""
    echo "Option B - Manual Vivado build:"
    echo "   1. Open Vivado Tcl Shell"
    echo "   2. cd $BOARD_DIR"
    echo "   3. source vivado_full_rebuild.tcl -notrace"
    echo "   4. Wait for build (~30-45 minutes)"
    echo "   5. Your .bin: $BOARD_DIR/pcileech_enigma_x1.bin"
    echo ""
    echo "To flash to your Enigma X1:"
    echo "   source vivado_flash.tcl -notrace"
fi

echo ""
print_header "Done!"
