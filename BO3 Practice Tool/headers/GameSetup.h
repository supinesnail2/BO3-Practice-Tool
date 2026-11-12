#pragma once

// Game Setup pages: game version (old/new patch), Workshop Stack loaded mods, and T7 Patch.

namespace BO3PT::GameSetup
{
	// Call once after bo3Directory and selfDirectory are known. Starts T7 Patch if auto start is on.
	void Init();

	void GameVersionFunc();
	void LoadedModsFunc();
	void T7PatchFunc();

	// One-line status for the sidebar, e.g. "Old patch" in yellow.
	void RenderSidebarStatus();
}
