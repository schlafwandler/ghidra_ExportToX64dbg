# ExportToX64dbg
A Ghidra script to export information to a x64dbg database.

## Features
  * Exports functions, function names (as labels), and function prototypes (as comments)
  * Exports labels for global variables
  * Exports bookmarks
  * Exports some (see Limitations) decompiled C statements (as comments)

## Installation
Copy `ExportToX64dbg.py` to your Ghidra scripts directory (the Script Manager has a button to show you all directories where Ghidra is looking for scripts).

If the script is not shown in the Script Manager, try the 'Refresh Script List` button.

## Usage

  * Run the script
  * Select a filename for the database (matching suffix will be appended automatically)
  * In x64dbg: Import the database (`File -> Import database`)

## Bugs/Limitations
  * Not the full decompiled source code gets exported as comments
At the moment the source code export is limited to elements that appear as `ClangStatement` in the `ClangTokenGroup` returned by `getCCodeMarkup()`.
This works fine for most variable assignments and function calls, but excludes most control flow altering constructs (like `if`, `for` or `while`).

## Similar projects
[GhidraX64Dbg](https://github.com/revolver-ocelot-saa/GhidraX64Dbg)
[ret-sync](https://github.com/bootleg/ret-sync)
[lst2x64dbg](https://github.com/utkonos/lst2x64dbg)
