# PixelForge Patch

A lightweight DLL that removes trial restrictions from PixelForge.

## What It Does

- Bypasses trial day checks via memory pattern scanning
- Removes nag screens and trial reminders
- Exe stays untouched — patches applied in-memory at runtime

## How It Works

The DLL masquerades as `version.dll` and sits alongside the PixelForge executable. On launch it:

1. Forwards all `version.dll` API calls to the real system DLL
2. Verifies the host EXE via hash before applying patches
3. Scans all committed memory regions for the trial check pattern
4. Patches the trial validation to force registered state

## Installation

1. Drop `version.dll` (compiled from this source) in the install folder
2. Run the executable — that's it

## Notes

- Built for **PixelForge x64** only. Other builds may not work.
- Uses memory pattern scanning — works across different versions.
- AV may flag the DLL — false positives are common with in-memory patching tools.
- For educational purposes only.

## Disclaimer

This project is for **educational and research purposes only**. Use at your own risk. The author is not responsible for any misuse or damage.

---

Cracked by **github.com/ofkits1**
