#!/usr/bin/env python3
"""Synthesize BAR models from captured MMIO traces.

Converts runtime MMIO access patterns into static register models
for deterministic BAR content generation.
"""

from collections import defaultdict
from typing import Any, Dict, List, Optional

from pcileechfwgenerator.device_clone.bar_model_loader import BarModel, RegisterSpec
from pcileechfwgenerator.device_clone.mmio_tracer import MmioAccess, MmioTrace
from pcileechfwgenerator.log_config import get_logger
from pcileechfwgenerator.string_utils import log_debug_safe, log_info_safe, safe_format

logger = get_logger(__name__)


def synthesize_model(trace: MmioTrace) -> BarModel:
    """Synthesize BAR model from captured MMIO trace.

    Algorithm:
    1. Group accesses by offset
    2. Infer width from most common access width per offset
    3. Reset value = first read value OR first write value (fallback)
    4. RW mask = OR of all written values (conservative estimate)
    5. Detect RW1C hint: write(1) followed by read(0) on same bit

    Args:
        trace: Captured MMIO trace

    Returns:
        BarModel ready for content generation

    Raises:
        ValueError: If trace is invalid or empty
    """
    if trace.bar_size <= 0:
        raise ValueError("Invalid BAR size in trace")

    if not trace.accesses:
        log_info_safe(
            logger,
            safe_format(
                "Empty trace for BAR{idx}, creating minimal model",
                idx=trace.bar_index
            ),
            prefix="SYNTH",
        )
        # Return minimal model for empty trace
        return BarModel(size=trace.bar_size, registers={})

    # Group accesses by offset
    by_offset: Dict[int, List[MmioAccess]] = defaultdict(list)
    for access in trace.accesses:
        by_offset[access.offset].append(access)

    registers: Dict[int, RegisterSpec] = {}

    for offset, accesses in sorted(by_offset.items()):
        # Infer width (most common)
        widths = [a.width for a in accesses]
        width = max(set(widths), key=widths.count)

        # Find reset value
        reset = 0
        reads = [a for a in accesses if a.operation ==
                 "R" and a.value is not None]
        writes = [a for a in accesses if a.operation == "W"]

        if reads:
            # First read typically represents reset/power-on state
            reset = reads[0].value
            log_debug_safe(
                logger,
                safe_format(
                    "BAR{bar} offset 0x{off:04X}: reset=0x{val:0{w}X} (from read)",
                    bar=trace.bar_index,
                    off=offset,
                    val=reset,
                    w=width * 2,
                ),
                prefix="SYNTH",
            )
        elif writes:
            # Fallback: use first write value as reset approximation
            reset = writes[0].value if writes[0].value is not None else 0
            log_debug_safe(
                logger,
                safe_format(
                    "BAR{bar} offset 0x{off:04X}: reset=0x{val:0{w}X} (from write)",
                    bar=trace.bar_index,
                    off=offset,
                    val=reset,
                    w=width * 2,
                ),
                prefix="SYNTH",
            )

        # Compute RW mask (conservative: OR all written values)
        rw_mask = 0
        for write in writes:
            if write.value is not None:
                rw_mask |= write.value

        # If no writes observed, assume fully writable
        if rw_mask == 0:
            rw_mask = (1 << (8 * width)) - 1
            log_debug_safe(
                logger,
                safe_format(
                    "BAR{bar} offset 0x{off:04X}: no writes, assuming fully RW",
                    bar=trace.bar_index,
                    off=offset,
                ),
                prefix="SYNTH",
            )

        # Detect RW1C behavior (simple heuristic)
        maybe_rw1c = _detect_rw1c(accesses)

        # Clamp values to width
        max_val = (1 << (8 * width)) - 1
        reset &= max_val
        rw_mask &= max_val

        registers[offset] = RegisterSpec(
            offset=offset,
            width=width,
            reset=reset,
            rw_mask=rw_mask,
            hints={"maybe_rw1c": maybe_rw1c},
        )

    log_info_safe(
        logger,
        safe_format(
            "Synthesized model for BAR{idx}: {nregs} registers from {naccess} accesses",
            idx=trace.bar_index,
            nregs=len(registers),
            naccess=len(trace.accesses),
        ),
        prefix="SYNTH",
    )

    return BarModel(size=trace.bar_size, registers=registers)


def _detect_rw1c(accesses: List[MmioAccess]) -> bool:
    """Detect potential RW1C (read/write-1-to-clear) behavior.

    Heuristic: If we see a write of non-zero value followed by
    a read that has fewer bits set, it may be RW1C.

    Args:
        accesses: List of accesses to same offset

    Returns:
        True if RW1C behavior detected
    """
    for i, access in enumerate(accesses[:-1]):
        next_access = accesses[i + 1]

        # Look for write followed by read
        if (
            access.operation == "W"
            and access.value is not None
            and access.value != 0
            and next_access.operation == "R"
            and next_access.value is not None
        ):
            # Check if any bits were cleared
            cleared_bits = access.value & ~next_access.value
            if cleared_bits:
                return True

    return False


def synthesize_bar_models(
    bdf: str,
    bars: List[Dict],
    cache_dir=None,
    force_recapture: bool = False,
    logger=None,
) -> Dict[int, BarModel]:
    """Synthesize BAR models for all memory BARs of a device.

    This is the high-level entry point that:
    1. Uses MmioTracer to capture MMIO access traces for each BAR
    2. Synthesizes register models from the traces
    3. Optionally caches results for reuse

    Args:
        bdf: PCI device BDF (e.g., "0000:03:00.0")
        bars: List of BAR info dicts with 'index', 'bar_type', 'size', etc.
        cache_dir: Optional directory to cache captured traces
        force_recapture: If True, ignore cached traces and recapture
        logger: Optional logger instance

    Returns:
        Dict mapping BAR index to synthesized BarModel
    """
    from pcileechfwgenerator.device_clone.mmio_tracer import MmioTracer
    import json
    from pathlib import Path
    
    log = logger or get_logger(__name__)
    result: Dict[int, BarModel] = {}
    
    # Filter to memory BARs only (MMIO doesn't apply to I/O BARs)
    memory_bars = [b for b in bars if b.get("bar_type", "").lower() == "memory"]
    
    if not memory_bars:
        log_info_safe(
            log,
            "No memory BARs found for MMIO learning",
            prefix="SYNTH"
        )
        return result
    
    # Check for cached models
    cache_file = None
    if cache_dir:
        cache_path = Path(cache_dir)
        cache_file = cache_path / f"bar_models_{bdf.replace(':', '_')}.json"
        
        if cache_file.exists() and not force_recapture:
            try:
                with open(cache_file, "r") as f:
                    cached = json.load(f)
                log_info_safe(
                    log,
                    safe_format("Loaded cached BAR models from {path}", path=cache_file),
                    prefix="SYNTH"
                )
                # Reconstruct BarModel objects from cached data
                for bar_idx_str, model_data in cached.items():
                    bar_idx = int(bar_idx_str)
                    registers = {}
                    for offset_str, reg_data in model_data.get("registers", {}).items():
                        offset = int(offset_str)
                        registers[offset] = RegisterSpec(
                            offset=offset,
                            width=reg_data.get("width", 4),
                            reset_value=reg_data.get("reset_value", 0),
                            rw_mask=reg_data.get("rw_mask", 0),
                            rw1c_mask=reg_data.get("rw1c_mask", 0),
                        )
                    result[bar_idx] = BarModel(
                        size=model_data.get("size", 0),
                        registers=registers
                    )
                return result
            except Exception as e:
                log_info_safe(
                    log,
                    safe_format("Cache read failed, will recapture: {err}", err=str(e)),
                    prefix="SYNTH"
                )
    
    # Initialize tracer
    try:
        tracer = MmioTracer(bdf)
    except (PermissionError, RuntimeError) as e:
        log_info_safe(
            log,
            safe_format(
                "MMIO tracer not available (requires bpftrace): {err}",
                err=str(e)
            ),
            prefix="SYNTH"
        )
        return result
    
    # Capture traces for each memory BAR
    for bar_info in memory_bars:
        bar_idx = bar_info.get("index", 0)
        bar_size = bar_info.get("size", 0)
        
        if bar_size == 0:
            continue
            
        try:
            log_info_safe(
                log,
                safe_format(
                    "Capturing MMIO trace for BAR{idx} (size=0x{size:X})",
                    idx=bar_idx,
                    size=bar_size
                ),
                prefix="SYNTH"
            )
            
            # Capture trace (short duration since device should already be probed)
            trace = tracer.capture_probe_trace(
                bar_index=bar_idx,
                duration_sec=2.0,
                trigger_rebind=False
            )
            
            # Synthesize model from trace
            model = synthesize_model(trace)
            result[bar_idx] = model
            
            log_info_safe(
                log,
                safe_format(
                    "Synthesized BAR{idx} model: {nregs} registers from {naccess} accesses",
                    idx=bar_idx,
                    nregs=len(model.registers),
                    naccess=len(trace.accesses)
                ),
                prefix="SYNTH"
            )
            
        except Exception as e:
            log_info_safe(
                log,
                safe_format(
                    "BAR{idx} trace capture failed: {err}",
                    idx=bar_idx,
                    err=str(e)
                ),
                prefix="SYNTH"
            )
    
    # Cache results if cache_dir provided
    if cache_file and result:
        try:
            cache_path.mkdir(parents=True, exist_ok=True)
            cached_data = {}
            for bar_idx, model in result.items():
                cached_data[str(bar_idx)] = {
                    "size": model.size,
                    "registers": {
                        str(offset): {
                            "offset": reg.offset,
                            "width": reg.width,
                            "reset_value": reg.reset_value,
                            "rw_mask": reg.rw_mask,
                            "rw1c_mask": reg.rw1c_mask,
                        }
                        for offset, reg in model.registers.items()
                    }
                }
            with open(cache_file, "w") as f:
                json.dump(cached_data, f, indent=2)
            log_info_safe(
                log,
                safe_format("Cached BAR models to {path}", path=cache_file),
                prefix="SYNTH"
            )
        except Exception as e:
            log_info_safe(
                log,
                safe_format("Failed to cache BAR models: {err}", err=str(e)),
                prefix="SYNTH"
            )
    
    return result
