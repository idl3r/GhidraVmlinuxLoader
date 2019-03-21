# Vmlinux loader for Ghidra

This extension can be used to load vmlinux kernel images into Ghidra. Output from droidimg is required.

## Usage

1. Run droidimg to get symbol file
```shell
    vmlinux.py --json <vmlinux> > <vmlinux>.sym.json
```
2. Make sure the generated .sym.json file is in the same directory of the iamge file.
3. Import the image file using Ghidra, and choose **Vmlinux Loader** as file format.
4. Run auto analysis

## Notes

