# PCILeech Firmware Generator

## Overview

PCILeech Firmware Generator is a Python-based tool for generating authentic PCIe DMA firmware from real donor hardware. It uses a 3-stage host-container-host pipeline:

1. **Stage 1 (Host)**: Collects PCIe device data via VFIO from the host system
2. **Stage 2 (Container or Local)**: Generates firmware artifacts from collected data using Jinja2 templating
3. **Stage 3 (Host)**: Runs Vivado synthesis on the host (optional)

The tool extracts donor configurations from local devices and generates unique firmware by analyzing real PCIe device register maps, configuration space, and capabilities. It produces SystemVerilog overlay files and COE configuration files that integrate with upstream pcileech-fpga HDL modules.

## User Preferences

Preferred communication style: Simple, everyday language.

## System Architecture

### Project Structure

- **`src/`**: Main source package (`pcileechfwgenerator`)
  - **`cli/`**: Command-line interface and VFIO handling
  - **`device_clone/`**: Core PCIe device analysis and cloning logic
  - **`templating/`**: Jinja2 template rendering and SystemVerilog generation
  - **`templates/`**: Jinja2 templates for SystemVerilog (`.sv.j2`) and TCL files
  - **`tui/`**: Terminal UI components built with Textual framework
  - **`utils/`**: Validators, file management, and utility functions
  - **`file_management/`**: Repository management and file discovery

- **`pcileech.py`**: Unified entry point that orchestrates the 3-stage pipeline
- **`scripts/`**: Development and maintenance scripts (version bumping, linting, validation)
- **`tests/`**: Pytest test suite with unit, integration, and TUI tests

### Core Design Patterns

**Template-Based Generation**: Uses Jinja2 templates with custom filters to generate SystemVerilog code. Templates are validated at build time with strict context validation to prevent security issues.

**Overlay Architecture**: Generates device-specific `.coe` configuration files that overlay onto upstream pcileech-fpga modules rather than modifying core HDL.

**VFIO Integration**: Linux-only VFIO subsystem access for reading real PCIe device configuration space and capabilities without kernel driver interference.

**Pydantic Models**: Configuration validation uses Pydantic for type checking and data validation throughout the pipeline.

### Key Components

- **`FirmwareBuilder`** (`src/build.py`): Main build orchestrator that coordinates device extraction, template rendering, and artifact generation
- **`TemplateRenderer`** (`src/templating/template_renderer.py`): Jinja2 environment with custom filters for SystemVerilog generation
- **`VFIOBinder`** (`src/cli/vfio_handler.py`): Manages VFIO device binding/unbinding for safe PCI device access
- **`ConfigSpaceManager`** (`src/device_clone/config_space_manager.py`): Parses 4KB PCIe configuration space
- **`PCILeechGenerator`** (`src/device_clone/generator.py`): Generates complete firmware packages from device configuration

### Testing Strategy

- Pytest with markers for `tui`, `unit`, and `integration` tests
- Mock-based testing for VFIO operations (no real hardware required in CI)
- Template syntax validation as part of CI pipeline
- SystemVerilog syntax linting for generated code

## External Dependencies

### Python Dependencies (requirements.txt)
- **psutil**: System resource monitoring
- **pydantic**: Configuration validation and serialization
- **aiofiles**: Async file I/O for build system
- **jinja2**: Template rendering for SystemVerilog/TCL generation
- **PyYAML**: YAML configuration parsing
- **colorlog**: Colored logging output

### TUI Dependencies (requirements-tui.txt)
- **textual**: Terminal UI framework
- **rich**: Rich text rendering
- **watchdog**: File system monitoring

### Development Dependencies (requirements-dev.txt)
- **pytest** ecosystem: Testing framework with coverage, mocking, async support
- **black/isort/flake8**: Code formatting and linting
- **mypy**: Static type checking
- **pre-commit**: Git hook management
- **sphinx**: Documentation generation

### External Tools
- **Vivado**: Xilinx FPGA synthesis toolchain (optional, Stage 3)
- **voltcyclone-fpga submodule**: Upstream pcileech-fpga HDL modules (in `lib/voltcyclone-fpga`)
- **usbloader**: For flashing LambdaConcept Squirrel/Screamer boards

### System Requirements
- **Linux**: Required for VFIO device access (host stages)
- **IOMMU**: Must be enabled in BIOS/UEFI for VFIO passthrough
- **Python 3.11+**: Minimum supported version