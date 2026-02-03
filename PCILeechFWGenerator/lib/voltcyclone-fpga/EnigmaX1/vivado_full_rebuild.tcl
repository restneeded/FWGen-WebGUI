#
# FULL REBUILD SCRIPT - Guarantees fresh .coe data is used
# RUN FROM WITHIN "Vivado Tcl Shell" WITH COMMAND:
# source vivado_full_rebuild.tcl -notrace
#
# This script:
# 1. Deletes any existing project to ensure clean state
# 2. Copies your donor .coe files to the IP directory
# 3. Creates fresh project with YOUR device IDs
# 4. Builds and produces .bin file
#

set project_name "pcileech_enigma_x1"
set origin_dir "."

puts "======================================================="
puts " PCILEECH ENIGMA X1 FULL REBUILD                       "
puts " Guaranteed fresh .coe data injection                  "
puts "======================================================="

# Step 1: Clean up any existing project
puts "-------------------------------------------------------"
puts " STEP 1: Cleaning up old project files                 "
puts "-------------------------------------------------------"
if {[file exists "./${project_name}"]} {
    puts "Removing old project directory..."
    file delete -force "./${project_name}"
}
if {[file exists "./${project_name}.xpr"]} {
    puts "Removing old project file..."
    file delete -force "./${project_name}.xpr"
}
# Clean up any stale cache/logs
foreach pattern {".Xil" "vivado*.jou" "vivado*.log" "ip_status_report.txt"} {
    foreach f [glob -nocomplain $pattern] {
        catch {file delete -force $f}
    }
}
puts "Cleanup complete."

# Step 2: Verify .coe files exist with donor data
puts "-------------------------------------------------------"
puts " STEP 2: Verifying donor .coe files                    "
puts "-------------------------------------------------------"
set coe_dir [file normalize "${origin_dir}/ip"]
set required_coe_files {
    "pcileech_cfgspace.coe"
    "pcileech_cfgspace_writemask.coe"
    "pcileech_bar_zero4k.coe"
}
set coe_valid 1
foreach coe_file $required_coe_files {
    set coe_path "$coe_dir/$coe_file"
    if {![file exists $coe_path]} {
        puts "ERROR: Missing required file: $coe_path"
        set coe_valid 0
    } else {
        # Read first line of config space to show device IDs
        if {$coe_file eq "pcileech_cfgspace.coe"} {
            set fp [open $coe_path r]
            set content [read $fp]
            close $fp
            # Find first hex data line (skip header)
            if {[regexp {([0-9a-fA-F]{8}),} $content match first_dword]} {
                set vendor_id [string range $first_dword 4 7]
                set device_id [string range $first_dword 0 3]
                puts "Found device IDs - Vendor: 0x$vendor_id, Device: 0x$device_id"
                # Warn if it looks like default/template values
                if {$vendor_id eq "ffff" || $vendor_id eq "FFFF"} {
                    puts "WARNING: Vendor ID is 0xFFFF - this looks like TEMPLATE data, not real donor!"
                    puts "WARNING: Make sure you ran the Python generator first!"
                }
            }
        }
        puts "OK: $coe_file"
    }
}
if {!$coe_valid} {
    puts "ERROR: Cannot proceed without required .coe files"
    puts "Run the Python generator first to create donor-specific .coe files"
    return 1
}

# Step 3: Generate project (this sources the generate script)
puts "-------------------------------------------------------"
puts " STEP 3: Creating fresh Vivado project                 "
puts "-------------------------------------------------------"
puts "Sourcing vivado_generate_project.tcl..."
source vivado_generate_project.tcl -notrace
puts "Project created successfully."

# Step 4: Open the project
puts "-------------------------------------------------------"
puts " STEP 4: Opening project and verifying IP cores        "
puts "-------------------------------------------------------"
open_project ./${project_name}/${project_name}.xpr

# Verify .bin generation is enabled
set impl_run [get_runs impl_1]
set bin_enabled [get_property STEPS.WRITE_BITSTREAM.ARGS.BIN_FILE $impl_run]
if {!$bin_enabled} {
    puts "Enabling .bin file generation..."
    set_property STEPS.WRITE_BITSTREAM.ARGS.BIN_FILE 1 $impl_run
}

# Step 5: Force regenerate all IP cores with fresh .coe data
puts "-------------------------------------------------------"
puts " STEP 5: Regenerating IP cores with donor data         "
puts "-------------------------------------------------------"

# Copy fresh .coe files AGAIN to IP directories (paranoid mode)
set ip_base_dir "./${project_name}/${project_name}.srcs/sources_1/ip"
foreach ip_name {"bram_pcie_cfgspace" "bram_bar_zero4k" "drom_pcie_cfgspace_writemask"} {
    set ip_dir "$ip_base_dir/$ip_name"
    if {[file exists $ip_dir]} {
        # Map IP name to .coe file
        switch $ip_name {
            "bram_pcie_cfgspace" {set coe_file "pcileech_cfgspace.coe"}
            "bram_bar_zero4k" {set coe_file "pcileech_bar_zero4k.coe"}
            "drom_pcie_cfgspace_writemask" {set coe_file "pcileech_cfgspace_writemask.coe"}
        }
        set src_coe "$coe_dir/$coe_file"
        set dst_coe "$ip_dir/$coe_file"
        if {[file exists $src_coe]} {
            file copy -force $src_coe $dst_coe
            puts "Copied fresh $coe_file to $ip_name"
        }
    }
}

# Force complete regeneration of IP cores
puts "Resetting and regenerating IP cores..."
foreach ip [get_ips] {
    set ip_name [get_property NAME $ip]
    puts "Processing IP: $ip_name"
    
    # Reset all targets to force regeneration
    reset_target all $ip
    
    # Upgrade IP if needed (handles version differences)
    catch {upgrade_ip -quiet $ip}
    
    # Generate targets fresh
    generate_target all $ip
    
    puts "  Regenerated: $ip_name"
}
puts "All IP cores regenerated with donor data."

# Step 6: Run synthesis
puts "-------------------------------------------------------"
puts " STEP 6: Running synthesis                             "
puts " (This takes 5-15 minutes)                             "
puts "-------------------------------------------------------"
reset_run synth_1
launch_runs synth_1 -jobs 4
wait_on_run synth_1

# Check synthesis status
set synth_status [get_property STATUS [get_runs synth_1]]
if {$synth_status ne "synth_design Complete!"} {
    puts "ERROR: Synthesis failed with status: $synth_status"
    return 1
}
puts "Synthesis completed successfully."

# Step 7: Run implementation and bitstream generation
puts "-------------------------------------------------------"
puts " STEP 7: Running implementation and bitstream          "
puts " (This takes 10-30 minutes)                            "
puts "-------------------------------------------------------"
reset_run impl_1
launch_runs impl_1 -to_step write_bitstream -jobs 4
wait_on_run impl_1

# Check implementation status
set impl_status [get_property STATUS [get_runs impl_1]]
if {$impl_status ne "write_bitstream Complete!"} {
    puts "ERROR: Implementation failed with status: $impl_status"
    return 1
}

# Step 8: Copy output files
puts "-------------------------------------------------------"
puts " STEP 8: Copying output files                          "
puts "-------------------------------------------------------"
set bin_src "./${project_name}/${project_name}.runs/impl_1/${project_name}_top.bin"
set bit_src "./${project_name}/${project_name}.runs/impl_1/${project_name}_top.bit"
set bin_dst "./${project_name}.bin"
set bit_dst "./${project_name}.bit"

if {[file exists $bin_src]} {
    file copy -force $bin_src $bin_dst
    puts "SUCCESS: Created $bin_dst"
    # Show file size as sanity check
    set bin_size [file size $bin_dst]
    puts "  File size: $bin_size bytes"
} else {
    puts "ERROR: .bin file not found at $bin_src"
    puts "Available files in impl_1:"
    foreach f [glob -nocomplain "./${project_name}/${project_name}.runs/impl_1/*"] {
        puts "  $f"
    }
    return 1
}

if {[file exists $bit_src]} {
    file copy -force $bit_src $bit_dst
    puts "SUCCESS: Created $bit_dst"
}

puts "======================================================="
puts " BUILD COMPLETE!                                       "
puts "======================================================="
puts ""
puts "Output files:"
puts "  ${project_name}.bin - Flash this to your Enigma X1"
puts "  ${project_name}.bit - Bitstream (optional)"
puts ""
puts "To flash, run: source vivado_flash.tcl -notrace"
puts "======================================================="
