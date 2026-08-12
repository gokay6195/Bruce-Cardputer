import os
import glob

Import("env")

def patch_amiibolink():
    """Patch ESP Amiibolink to include Arduino.h (fixes 'Serial' and 'delay' not declared)"""
    lib_paths = glob.glob(".pio/libdeps/*/ESP Amiibolink/src/amiibolink.cpp")
    
    for path in lib_paths:
        with open(path, 'r') as f:
            content = f.read()
        
        # Check if already patched
        if '#include <Arduino.h>' in content:
            print(f"Already patched: {path}")
            continue
        
        # Add Arduino.h include at the top
        content = '#include <Arduino.h>\n' + content
        
        with open(path, 'w') as f:
            f.write(content)
        
        print(f"Patched: {path}")

patch_amiibolink()
