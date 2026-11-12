# BO3 Practice Tool (Game Setup edition)

A modified build of [Joshr520's BO3 Practice Tool](https://github.com/Joshr520/BO3-Practice-Tool) for Call of Duty: Black Ops III Zombies. All the original features are kept; this version adds a **Game Setup** section, fixes weapon loadouts, and has a new icon.

## What's new

**Game Setup** (new sidebar group, with a status line at the top of the sidebar):

- **Game Version**: shows whether `BlackOps3.exe` is the old (speedrun downgrade) or new (current Steam) patch. Save both exes and switch between them with one click. They are kept in an `Exe Versions` folder in the game directory.
- **T7 Patch**: finds T7 Patch, shows whether it is running and warns when BO3 was started before it. Includes a **Start T7 Patch + BO3** button and an optional auto-start. T7 Patch itself is not included; it is launched as a separate program.

**Weapon loadouts now work**:

- The **Use in game** checkbox is on by default and remembered, along with your chosen loadout.
- The loadout is written for the game as soon as you change it, because BO3 only reads it while a map loads. Previously it was only written while the tool was toggled on and the checkbox (off on every launch) was ticked.
- Your optics, attachments and camos apply to wall-buy, box and Pack-a-Punch weapons.

**Other**:

- New icon: orange "III" in a stopwatch.
- Disk and process checks run in the background, so the window stays responsive when the game is on a slow or busy drive.
- **Portable, Windows 10 and 11**: the Visual C++ runtime is included, and settings are kept next to the exe however it is started, so the folder can live anywhere (even a USB stick) with no installer.

## Install

1. Download `BO3-Practice-Tool.zip` from [Releases](../../releases) and extract it anywhere. Works on Windows 10 and 11 (64-bit) with no installer; needs a graphics driver with Vulkan support, which any GPU from the last several years has.
2. Run `BO3 Practice Tool.exe` and select your `Call of Duty Black Ops III` folder when asked.
3. If the in-game compiler files are missing, use the download button at the top of the sidebar. It fetches them from the original tool's releases.

Windows may warn about an unsigned app, and some antivirus programs flag the in-game compiler. Add an exclusion if needed (the original tool's README says the same).

## Using weapon loadouts

1. In **Weapon Loadouts**, create a preset and pick optics, attachments and camos for each gun. Every click saves.
2. Leave **Use in game** ticked.
3. Start BO3, turn the tool on **at the main menu**, then start the map.

Changes made mid-match apply from the next map load.

## Building

Visual Studio 2022 (or Build Tools) with the C++ workload, and the [Vulkan SDK](https://vulkan.lunarg.com/) (`VULKAN_SDK` set). Header-only libraries and import libraries are in `deps/`, wired in by `Directory.Build.props` / `Directory.Build.targets`.

```
MSBuild "BO3 Practice Tool.sln" /p:Configuration=Release /p:Platform=x64
```

Copy `libcurl.dll`, `miniz.dll`, `zlib1.dll`, `SDL2.dll` and the Visual C++ runtime (`msvcp140.dll`, `vcruntime140.dll`, `vcruntime140_1.dll` from `VC\Redist\MSVC\<version>\x64\Microsoft.VC143.CRT`) next to the exe, along with the `Fonts`, `Resource Images` and `Exported Splits` folders.

## Credits

- Original tool and in-game scripts: [Joshr520/BO3-Practice-Tool](https://github.com/Joshr520/BO3-Practice-Tool) (MIT license, see `LICENSE.txt`).
- In-game compiler: serious's T7 compiler, distributed with the original tool.
- UI: Dear ImGui and Walnut; libcurl, miniz, zlib, SDL2, RapidJSON, RapidXML, GLM.

Not affiliated with Activision or Treyarch.
