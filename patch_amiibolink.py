import os
import glob

Import("env")

def patch_lib(file_glob, include_name):
    """Patch une lib externe pour ajouter Arduino.h"""
    lib_paths = glob.glob(file_glob)
    for path in lib_paths:
        with open(path, 'r') as f:
            content = f.read()
        if '#include <Arduino.h>' in content:
            print(f"Already patched: {path}")
            continue
        content = '#include <Arduino.h>\n' + content
        with open(path, 'w') as f:
            f.write(content)
        print(f"Patched: {path}")

def patch_external_libs():
    """Patch toutes les libs externes qui ont besoin d'Arduino.h"""
    # Patch ESP Amiibolink
    patch_lib(".pio/libdeps/*/ESP Amiibolink/src/amiibolink.cpp", "amiibolink")
    # Patch ESP Chameleon Ultra
    patch_lib(".pio/libdeps/*/ESP Chameleon Ultra/src/chameleonUltra.cpp", "chameleonUltra")

patch_external_libs()
