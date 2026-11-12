#include <Windows.h>
#include <bcrypt.h>
#include <TlHelp32.h>
#include <shellapi.h>
#include <Shobjidl.h>

#include <atomic>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

#include "GameSetup.h"
#include "GlobalData.h"
#include "ImGuiHelper.h"
#include "Walnut/Application.h"
#include "Walnut/FileFormats/json.h"
#include "Walnut/Logger.h"
#include "Fonts/Icons.h"

#pragma comment(lib, "bcrypt.lib")

namespace fs = std::filesystem;
using WLog = Walnut::Logger;
using WMT = Walnut::MessageType;
using WJson = Walnut::JSONBuilder;
using TextFont = ImGuiHelper::TextFont;

namespace BO3PT::GameSetup
{
    // ---------------------------------------------------------------- shared helpers

    static const ImVec4 kGreen(0.3f, 0.85f, 0.4f, 1.0f);
    static const ImVec4 kRed(0.95f, 0.35f, 0.35f, 1.0f);
    static const ImVec4 kYellow(0.95f, 0.8f, 0.3f, 1.0f);
    static const ImVec4 kGrey(0.65f, 0.65f, 0.65f, 1.0f);

    enum class PatchKind { Unknown, Scanning, Old, New };

    struct KnownBuild {
        const char* sha256;
        const char* label;
        PatchKind kind;
    };

    // SHA-256 of BlackOps3.exe for the builds we know about
    static const KnownBuild kKnownBuilds[] = {
        { "51CA63BBC660E0826943C60DA67606F6BCB4B3B519528B5E0548C68C9423A323", "New patch (current Steam, build 24784313)", PatchKind::New },
        { "66B95EB4667BD5B3B3D230E7BED1D29CCD261D48CA2699F01216C863BE24FF44", "Old patch (speedrun downgrade)", PatchKind::Old },
        { "9BA98DBA41E18EF47DE6C63937340F8EAE7CB251F8FBC2E78D70047B64AA15B5", "Old patch (build 21201493)", PatchKind::Old },
    };

    static const KnownBuild* FindBuild(const std::string& hash)
    {
        for (const KnownBuild& build : kKnownBuilds) {
            if (_stricmp(build.sha256, hash.c_str()) == 0) {
                return &build;
            }
        }
        return nullptr;
    }

    static std::wstring Widen(const std::string& s)
    {
        if (s.empty()) {
            return L"";
        }
        int len = MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0);
        std::wstring out(len, L'\0');
        MultiByteToWideChar(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), len);
        return out;
    }

    static std::string Narrow(const std::wstring& s)
    {
        if (s.empty()) {
            return "";
        }
        int len = WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), nullptr, 0, nullptr, nullptr);
        std::string out(len, '\0');
        WideCharToMultiByte(CP_UTF8, 0, s.data(), (int)s.size(), out.data(), len, nullptr, nullptr);
        return out;
    }

    static fs::path GameDir()
    {
        fs::path p = fs::path(Widen(bo3Directory));
        if (!p.has_filename()) {
            p = p.parent_path();
        }
        return p;
    }

    static fs::path ExeVersionsDir() { return GameDir() / L"Exe Versions"; }
    static fs::path OldSlot() { return ExeVersionsDir() / L"BlackOps3.old.exe"; }
    static fs::path NewSlot() { return ExeVersionsDir() / L"BlackOps3.new.exe"; }

    static std::string Sha256File(const fs::path& path)
    {
        std::ifstream file(path, std::ios::binary);
        if (!file) {
            return "";
        }
        BCRYPT_ALG_HANDLE alg = nullptr;
        BCRYPT_HASH_HANDLE hash = nullptr;
        if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&alg, BCRYPT_SHA256_ALGORITHM, nullptr, 0))) {
            return "";
        }
        std::string result;
        if (BCRYPT_SUCCESS(BCryptCreateHash(alg, &hash, nullptr, 0, nullptr, 0, 0))) {
            std::vector<char> buffer(4 * 1024 * 1024);
            bool ok = true;
            while (file) {
                file.read(buffer.data(), buffer.size());
                std::streamsize got = file.gcount();
                if (got > 0 && !BCRYPT_SUCCESS(BCryptHashData(hash, (PUCHAR)buffer.data(), (ULONG)got, 0))) {
                    ok = false;
                    break;
                }
            }
            unsigned char digest[32];
            if (ok && BCRYPT_SUCCESS(BCryptFinishHash(hash, digest, sizeof(digest), 0))) {
                static const char* hex = "0123456789ABCDEF";
                for (unsigned char c : digest) {
                    result += hex[c >> 4];
                    result += hex[c & 15];
                }
            }
            BCryptDestroyHash(hash);
        }
        BCryptCloseAlgorithmProvider(alg, 0);
        return result;
    }

    struct ProcInfo {
        DWORD pid = 0;
        ULONGLONG started = 0; // FILETIME as 64-bit, 0 if unknown
    };

    // Scans all processes (a few ms). Only call from the worker thread or in response to a click.
    static ProcInfo FindProcessNow(const std::wstring& exeName)
    {
        ProcInfo info;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) {
            return info;
        }
        PROCESSENTRY32W entry{ sizeof(entry) };
        if (Process32FirstW(snap, &entry)) {
            do {
                if (_wcsicmp(entry.szExeFile, exeName.c_str()) == 0) {
                    info.pid = entry.th32ProcessID;
                    HANDLE proc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, info.pid);
                    if (proc) {
                        FILETIME created, exited, kernel, user;
                        if (GetProcessTimes(proc, &created, &exited, &kernel, &user)) {
                            info.started = ((ULONGLONG)created.dwHighDateTime << 32) | created.dwLowDateTime;
                        }
                        CloseHandle(proc);
                    }
                    break;
                }
            } while (Process32NextW(snap, &entry));
        }
        CloseHandle(snap);
        return info;
    }

    static bool CopyVerified(const fs::path& from, const fs::path& to, std::string& error)
    {
        std::error_code ec;
        fs::path temp = to;
        temp += L".tmp";
        if (!fs::copy_file(from, temp, fs::copy_options::overwrite_existing, ec)) {
            error = "Copy failed: " + ec.message();
            return false;
        }
        if (fs::file_size(temp, ec) != fs::file_size(from, ec)) {
            fs::remove(temp, ec);
            error = "Copy was incomplete.";
            return false;
        }
        fs::rename(temp, to, ec);
        if (ec) {
            fs::remove(temp, ec);
            error = "Could not replace the file: " + ec.message();
            return false;
        }
        return true;
    }

    static WJson LoadSettings()
    {
        std::string path = selfDirectory + "\\settings.json";
        if (!fs::exists(path)) {
            WJson::WriteEmpty(path);
        }
        return WJson::FromFile(path);
    }

    // ---------------------------------------------------------------- background scanner
    // Hashing a 140 MB exe takes a moment, so a worker thread keeps these results fresh.

    struct HashEntry {
        uintmax_t size = 0;
        fs::file_time_type written;
        std::string hash;
    };

    struct T7Settings {
        bool found = false;
        bool friendsOnly = false;
        bool hasPassword = false;
        bool hasName = false;
    };

    // Everything the pages show that needs the disk or a process scan. The game drive can be a slow
    // USB disk, so only the worker thread touches it; the UI thread just copies this each frame.
    struct Snapshot {
        bool ready = false; // false until the worker's first pass
        bool exeExists = false;
        bool oldExists = false;
        bool newExists = false;
        ProcInfo game;
        ProcInfo t7;
        T7Settings t7Settings;
    };

    static std::mutex s_Lock;
    static std::map<fs::path, HashEntry> s_Hashes; // guarded by s_Lock
    static std::map<fs::path, std::chrono::steady_clock::time_point> s_HashFailed; // guarded by s_Lock
    static Snapshot s_Snap;                        // guarded by s_Lock
    static std::string s_T7PathShared;             // guarded by s_Lock, copy of s_T7Path for the worker
    static std::atomic<bool> s_WorkerStarted = false;
    static std::atomic<bool> s_RescanNow = false;

    static Snapshot GetSnapshot()
    {
        std::lock_guard<std::mutex> lock(s_Lock);
        return s_Snap;
    }

    static std::string CachedHash(const fs::path& path)
    {
        std::lock_guard<std::mutex> lock(s_Lock);
        auto it = s_Hashes.find(path);
        return it == s_Hashes.end() ? "" : it->second.hash;
    }

    static void RefreshHash(const fs::path& path)
    {
        std::error_code ec;
        if (!fs::exists(path, ec)) {
            std::lock_guard<std::mutex> lock(s_Lock);
            s_Hashes.erase(path);
            return;
        }
        uintmax_t size = fs::file_size(path, ec);
        fs::file_time_type written = fs::last_write_time(path, ec);
        {
            std::lock_guard<std::mutex> lock(s_Lock);
            auto it = s_Hashes.find(path);
            if (it != s_Hashes.end() && it->second.size == size && it->second.written == written && !it->second.hash.empty()) {
                return;
            }
            // A file we couldn't read (e.g. locked by Steam) is retried every 30s, not every loop
            auto failed = s_HashFailed.find(path);
            if (failed != s_HashFailed.end() && std::chrono::steady_clock::now() - failed->second < std::chrono::seconds(30)) {
                return;
            }
        }
        std::string hash = Sha256File(path);
        std::lock_guard<std::mutex> lock(s_Lock);
        s_Hashes[path] = { size, written, hash };
        if (hash.empty()) {
            s_HashFailed[path] = std::chrono::steady_clock::now();
        }
        else {
            s_HashFailed.erase(path);
        }
    }

    static T7Settings ReadT7SettingsFrom(const std::string& t7Path)
    {
        T7Settings out;
        if (t7Path.empty()) {
            return out;
        }
        fs::path settings = fs::path(Widen(t7Path)).parent_path() / L"settings.json";
        std::error_code ec;
        if (!fs::exists(settings, ec)) {
            return out;
        }
        WJson builder = WJson::FromFile(Narrow(settings.wstring()));
        rapidjson::Document& doc = builder.GetDocument();
        if (!doc.IsObject()) {
            return out;
        }
        out.found = true;
        if (doc.HasMember("isfriendsonly") && doc["isfriendsonly"].IsBool()) out.friendsOnly = doc["isfriendsonly"].GetBool();
        if (doc.HasMember("networkpassword") && doc["networkpassword"].IsString()) out.hasPassword = doc["networkpassword"].GetStringLength() > 0;
        if (doc.HasMember("playername") && doc["playername"].IsString()) out.hasName = doc["playername"].GetStringLength() > 0;
        return out;
    }

    static void Worker()
    {
        int tick = 0;
        while (true) {
            bool rescan = s_RescanNow.exchange(false);
            std::string t7Path;
            {
                std::lock_guard<std::mutex> lock(s_Lock);
                t7Path = s_T7PathShared;
            }

            // Cheap checks every second: processes and file presence
            Snapshot snap;
            snap.ready = true;
            snap.game = FindProcessNow(L"BlackOps3.exe");
            if (!t7Path.empty()) {
                snap.t7 = FindProcessNow(fs::path(Widen(t7Path)).filename().wstring());
            }
            if (!bo3Directory.empty()) {
                std::error_code ec;
                snap.exeExists = fs::exists(GameDir() / L"BlackOps3.exe", ec);
                snap.oldExists = fs::exists(OldSlot(), ec);
                snap.newExists = fs::exists(NewSlot(), ec);
            }
            if (tick % 5 == 0 || rescan) {
                snap.t7Settings = ReadT7SettingsFrom(t7Path);
            }
            else {
                std::lock_guard<std::mutex> lock(s_Lock);
                snap.t7Settings = s_Snap.t7Settings;
            }
            {
                std::lock_guard<std::mutex> lock(s_Lock);
                s_Snap = snap;
            }

            // Hashes less often (each file is only re-read when it changes)
            if (!bo3Directory.empty()) {
                if (tick % 2 == 0 || rescan) {
                    RefreshHash(GameDir() / L"BlackOps3.exe");
                    RefreshHash(OldSlot());
                    RefreshHash(NewSlot());
                }
            }
            tick++;
            for (int i = 0; i < 10 && !s_RescanNow.load(); i++) {
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        }
    }

    // ---------------------------------------------------------------- T7 Patch

    static std::string s_T7Path;
    static bool s_T7AutoStart = false;
    static std::string s_T7Message;

    static std::string FindT7Patch()
    {
        char* profile = nullptr;
        size_t len = 0;
        if (_dupenv_s(&profile, &len, "USERPROFILE") || !profile) {
            return "";
        }
        fs::path desktop = fs::path(profile) / "Desktop";
        free(profile);
        std::error_code ec;
        fs::path best;
        for (const fs::directory_entry& dir : fs::directory_iterator(desktop, ec)) {
            std::wstring name = dir.path().filename().wstring();
            if (!dir.is_directory(ec) || _wcsnicmp(name.c_str(), L"t7patch", 7) != 0) {
                continue;
            }
            for (const fs::directory_entry& file : fs::directory_iterator(dir.path(), ec)) {
                std::wstring fname = file.path().filename().wstring();
                if (_wcsnicmp(fname.c_str(), L"t7patch", 7) == 0 && file.path().extension() == L".exe") {
                    // Prefer the plain folder name over copies like "(2)"
                    if (best.empty() || dir.path().wstring().size() < best.parent_path().wstring().size()) {
                        best = file.path();
                    }
                }
            }
        }
        return best.empty() ? "" : Narrow(best.wstring());
    }

    static void SaveT7Settings()
    {
        {
            std::lock_guard<std::mutex> lock(s_Lock);
            s_T7PathShared = s_T7Path;
        }
        s_RescanNow = true;
        WJson builder = LoadSettings();
        builder.ModifyString(builder.GetDocument(), "T7 Patch Path", s_T7Path);
        builder.ModifyBool(builder.GetDocument(), "Auto Start T7 Patch", s_T7AutoStart);
        builder.SaveToFile(selfDirectory + "\\settings.json");
    }

    static std::wstring T7ExeName()
    {
        return fs::path(Widen(s_T7Path)).filename().wstring();
    }

    static bool StartT7Patch()
    {
        if (s_T7Path.empty() || !fs::exists(Widen(s_T7Path))) {
            s_T7Message = "T7 Patch not found. Use Browse to pick t7patch_2.04.exe.";
            return false;
        }
        if (FindProcessNow(T7ExeName()).pid) {
            s_T7Message = "T7 Patch is already running.";
            return true;
        }
        fs::path exe = Widen(s_T7Path);
        HINSTANCE result = ShellExecuteW(nullptr, L"open", exe.c_str(), nullptr, exe.parent_path().c_str(), SW_SHOWNORMAL);
        if ((INT_PTR)result <= 32) {
            s_T7Message = "Windows could not start T7 Patch (error " + std::to_string((INT_PTR)result) + ").";
            WLog::Log(WMT::Error, s_T7Message);
            return false;
        }
        s_T7Message = "T7 Patch started.";
        WLog::Log(WMT::Success, "Started T7 Patch");
        return true;
    }

    static bool LaunchGame(std::string& message)
    {
        fs::path exe = GameDir() / L"BlackOps3.exe";
        if (FindProcessNow(L"BlackOps3.exe").pid) {
            message = "Black Ops III is already running.";
            return false;
        }
        HINSTANCE result = ShellExecuteW(nullptr, L"open", exe.c_str(), nullptr, GameDir().c_str(), SW_SHOWNORMAL);
        if ((INT_PTR)result <= 32) {
            message = "Windows could not start BlackOps3.exe (error " + std::to_string((INT_PTR)result) + ").";
            return false;
        }
        message = "Black Ops III is starting.";
        return true;
    }

    static std::string BrowseForExe()
    {
        std::string out;
        IFileOpenDialog* dialog = nullptr;
        if (SUCCEEDED(CoCreateInstance(CLSID_FileOpenDialog, nullptr, CLSCTX_ALL, IID_IFileOpenDialog, (void**)&dialog))) {
            COMDLG_FILTERSPEC filter[] = { { L"Programs", L"*.exe" } };
            dialog->SetFileTypes(1, filter);
            dialog->SetTitle(L"Select t7patch exe");
            if (SUCCEEDED(dialog->Show(nullptr))) {
                IShellItem* item = nullptr;
                if (SUCCEEDED(dialog->GetResult(&item))) {
                    PWSTR path = nullptr;
                    if (SUCCEEDED(item->GetDisplayName(SIGDN_FILESYSPATH, &path))) {
                        out = Narrow(path);
                        CoTaskMemFree(path);
                    }
                    item->Release();
                }
            }
            dialog->Release();
        }
        return out;
    }

    // ---------------------------------------------------------------- Init

    void Init()
    {
        WJson builder = LoadSettings();
        rapidjson::Document& doc = builder.GetDocument();
        if (doc.IsObject() && doc.HasMember("T7 Patch Path") && doc["T7 Patch Path"].IsString()) {
            s_T7Path = doc["T7 Patch Path"].GetString();
        }
        if (doc.IsObject() && doc.HasMember("Auto Start T7 Patch") && doc["Auto Start T7 Patch"].IsBool()) {
            s_T7AutoStart = doc["Auto Start T7 Patch"].GetBool();
        }
        if (s_T7Path.empty() || !fs::exists(Widen(s_T7Path))) {
            std::string found = FindT7Patch();
            if (!found.empty()) {
                s_T7Path = found;
                SaveT7Settings();
            }
        }
        {
            std::lock_guard<std::mutex> lock(s_Lock);
            s_T7PathShared = s_T7Path;
        }
        if (s_T7AutoStart) {
            StartT7Patch();
        }
        if (!s_WorkerStarted.exchange(true)) {
            std::thread(Worker).detach();
        }
    }

    // ---------------------------------------------------------------- shared UI bits

    static void Title(const char* text)
    {
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 25.0f);
        TextFont::Render(text, titleFont);
        ImGui::Separator();
        ImGui::Spacing();
    }

    static void Indent() { ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 25.0f); }

    struct VersionView {
        std::string hash;
        const KnownBuild* build = nullptr;
        PatchKind kind = PatchKind::Unknown;
        std::string label;
    };

    static VersionView CurrentVersion()
    {
        VersionView view;
        fs::path exe = GameDir() / L"BlackOps3.exe";
        Snapshot snap = GetSnapshot();
        if (!snap.ready) {
            view.kind = PatchKind::Scanning;
            view.label = "Checking...";
            return view;
        }
        if (bo3Directory.empty() || !snap.exeExists) {
            view.label = "BlackOps3.exe not found";
            return view;
        }
        view.hash = CachedHash(exe);
        if (view.hash.empty()) {
            view.kind = PatchKind::Scanning;
            view.label = "Checking...";
            return view;
        }
        view.build = FindBuild(view.hash);
        if (view.build) {
            view.kind = view.build->kind;
            view.label = view.build->label;
        }
        else if (view.hash == CachedHash(OldSlot())) {
            view.kind = PatchKind::Old;
            view.label = "Old patch (your saved old exe)";
        }
        else if (view.hash == CachedHash(NewSlot())) {
            view.kind = PatchKind::New;
            view.label = "New patch (your saved new exe)";
        }
        else {
            view.label = "Unknown version";
        }
        return view;
    }

    static ImVec4 KindColor(PatchKind kind)
    {
        switch (kind) {
        case PatchKind::New: return kGreen;
        case PatchKind::Old: return kYellow;
        case PatchKind::Scanning: return kGrey;
        default: return kRed;
        }
    }

    void RenderSidebarStatus()
    {
        VersionView view = CurrentVersion();
        const char* word = view.kind == PatchKind::New ? "New patch" : view.kind == PatchKind::Old ? "Old patch" : view.kind == PatchKind::Scanning ? "Checking version..." : "Unknown version";
        ImGui::TextColored(KindColor(view.kind), ICON_FA_CODE_BRANCH " BO3: %s", word);

        if (GetSnapshot().t7.pid) {
            ImGui::TextColored(kGreen, ICON_FA_SHIELD " T7 Patch running");
        }
        else {
            ImGui::TextColored(kRed, ICON_FA_SHIELD " T7 Patch not running");
        }
    }

    // ---------------------------------------------------------------- Game Version page

    static std::string s_VersionMessage;

    static void SwitchTo(PatchKind target)
    {
        fs::path slot = target == PatchKind::Old ? OldSlot() : NewSlot();
        fs::path exe = GameDir() / L"BlackOps3.exe";
        std::error_code ec;
        if (FindProcessNow(L"BlackOps3.exe").pid) {
            s_VersionMessage = "Close Black Ops III first, then switch.";
            return;
        }
        if (!fs::exists(slot, ec)) {
            s_VersionMessage = "No saved exe for that version yet.";
            return;
        }
        std::string current = CachedHash(exe);
        std::string slotHash = CachedHash(slot);
        if (!current.empty() && current == slotHash) {
            s_VersionMessage = "You're already on that version.";
            return;
        }
        // Keep a copy of the current exe if it isn't saved anywhere yet
        if (fs::exists(exe, ec) && current != CachedHash(OldSlot()) && current != CachedHash(NewSlot())) {
            std::string tag = current.empty() ? "unknown" : current.substr(0, 8);
            fs::path backup = ExeVersionsDir() / Widen("BlackOps3.backup-" + tag + ".exe");
            std::string error;
            if (!fs::exists(backup, ec) && !CopyVerified(exe, backup, error)) {
                s_VersionMessage = "Could not back up the current exe, nothing was changed. " + error;
                return;
            }
        }
        std::string error;
        if (!CopyVerified(slot, exe, error)) {
            s_VersionMessage = "Switch failed, nothing was changed. " + error;
            WLog::Log(WMT::Error, "Exe switch failed: " + error);
            return;
        }
        s_RescanNow = true;
        s_VersionMessage = target == PatchKind::Old
            ? "Switched to the old patch. Start the game with the button below, not from Steam, or Steam may update it."
            : "Switched to the new patch.";
        WLog::Log(WMT::Success, target == PatchKind::Old ? "Switched BO3 to old patch" : "Switched BO3 to new patch");
    }

    static void SaveCurrentAs(PatchKind target)
    {
        fs::path exe = GameDir() / L"BlackOps3.exe";
        std::error_code ec;
        fs::create_directories(ExeVersionsDir(), ec);
        std::string error;
        if (!CopyVerified(exe, target == PatchKind::Old ? OldSlot() : NewSlot(), error)) {
            s_VersionMessage = "Could not save the exe. " + error;
            return;
        }
        s_RescanNow = true;
        s_VersionMessage = target == PatchKind::Old ? "Saved the current exe as your old patch." : "Saved the current exe as your new patch.";
    }

    static void SlotRow(const char* name, const fs::path& slot, bool exists)
    {
        Indent();
        ImGui::Text("%s", name);
        ImGui::SameLine(200.0f);
        if (!exists) {
            ImGui::TextColored(kRed, "not saved");
            return;
        }
        std::string hash = CachedHash(slot);
        const KnownBuild* build = hash.empty() ? nullptr : FindBuild(hash);
        if (hash.empty()) {
            ImGui::TextColored(kGrey, "checking...");
        }
        else {
            ImGui::TextColored(build ? KindColor(build->kind) : kGrey, "%s", build ? build->label : "saved (unrecognised build)");
        }
    }

    void GameVersionFunc()
    {
        Title("Game Version");
        VersionView view = CurrentVersion();

        Indent();
        ImGui::Text("You're on:");
        ImGui::SameLine();
        ImGui::TextColored(KindColor(view.kind), "%s", view.label.c_str());
        if (!view.hash.empty()) {
            Indent();
            ImGui::TextColored(kGrey, "SHA-256 %s", view.hash.c_str());
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        Indent();
        TextFont::Render("Saved versions", sidebarFont);
        Snapshot snap = GetSnapshot();
        SlotRow("Old patch exe", OldSlot(), snap.oldExists);
        SlotRow("New patch exe", NewSlot(), snap.newExists);
        Indent();
        ImGui::TextColored(kGrey, "Stored in %s", Narrow(ExeVersionsDir().wstring()).c_str());

        ImGui::Spacing();
        Indent();
        bool running = snap.game.pid != 0;
        if (running) {
            ImGui::BeginDisabled();
        }
        bool hasOld = snap.oldExists;
        bool hasNew = snap.newExists;
        if (!hasOld) ImGui::BeginDisabled();
        if (ImGui::Button("Switch to Old Patch", ImVec2(220, 35))) {
            SwitchTo(PatchKind::Old);
        }
        if (!hasOld) ImGui::EndDisabled();
        ImGui::SameLine();
        if (!hasNew) ImGui::BeginDisabled();
        if (ImGui::Button("Switch to New Patch", ImVec2(220, 35))) {
            SwitchTo(PatchKind::New);
        }
        if (!hasNew) ImGui::EndDisabled();

        Indent();
        if (ImGui::Button("Save current exe as Old", ImVec2(220, 30))) {
            SaveCurrentAs(PatchKind::Old);
        }
        ImGui::SameLine();
        if (ImGui::Button("Save current exe as New", ImVec2(220, 30))) {
            SaveCurrentAs(PatchKind::New);
        }
        if (running) {
            ImGui::EndDisabled();
            Indent();
            ImGui::TextColored(kYellow, ICON_FA_TRIANGLE_EXCLAMATION " Close Black Ops III to switch versions.");
        }

        if (!s_VersionMessage.empty()) {
            ImGui::Spacing();
            Indent();
            ImGui::PushTextWrapPos(ImGui::GetContentRegionMax().x - 25.0f);
            ImGui::TextWrapped("%s", s_VersionMessage.c_str());
            ImGui::PopTextWrapPos();
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        Indent();
        ImGui::PushTextWrapPos(ImGui::GetContentRegionMax().x - 25.0f);
        ImGui::TextColored(kGrey, "Old patch: for speedrunning. Launching BO3 from Steam can update it back to the new patch, so use Start T7 Patch + BO3 on the T7 Patch page.\n"
            "New patch: the current Steam version.");
        ImGui::PopTextWrapPos();
    }

    // ---------------------------------------------------------------- T7 Patch page

    static std::atomic<bool> s_Launching = false;
    static std::mutex s_LaunchMessageLock;
    static std::string s_LaunchMessage;

    static void LaunchWithT7()
    {
        bool wasRunning = FindProcessNow(T7ExeName()).pid != 0;
        std::string message;
        if (!StartT7Patch()) {
            message = s_T7Message;
        }
        else {
            if (!wasRunning) {
                // Give T7 Patch a moment to start watching for the game
                std::this_thread::sleep_for(std::chrono::seconds(4));
            }
            LaunchGame(message);
        }
        {
            std::lock_guard<std::mutex> lock(s_LaunchMessageLock);
            s_LaunchMessage = message;
        }
        s_Launching = false;
    }

    void T7PatchFunc()
    {
        Title("T7 Patch");

        Indent();
        ImGui::Text("Location:");
        ImGui::SameLine();
        ImGui::TextColored(s_T7Path.empty() ? kRed : kGrey, "%s", s_T7Path.empty() ? "not found" : s_T7Path.c_str());
        ImGui::SameLine();
        if (ImGui::Button(ICON_FA_FOLDER_OPEN " Browse", ImVec2(110, 25))) {
            std::string picked = BrowseForExe();
            if (!picked.empty()) {
                s_T7Path = picked;
                SaveT7Settings();
            }
        }

        Snapshot snap = GetSnapshot();
        ProcInfo t7 = s_T7Path.empty() ? ProcInfo{} : snap.t7;
        ProcInfo game = snap.game;

        Indent();
        ImGui::Text("Status:");
        ImGui::SameLine();
        if (t7.pid) {
            ImGui::TextColored(kGreen, ICON_FA_CIRCLE_CHECK " Running");
        }
        else {
            ImGui::TextColored(kRed, ICON_FA_CIRCLE_XMARK " Not running");
        }

        if (game.pid) {
            Indent();
            if (!t7.pid) {
                ImGui::TextColored(kRed, ICON_FA_TRIANGLE_EXCLAMATION " BO3 is running without T7 Patch. Close BO3, start T7 Patch, then start BO3.");
            }
            else if (t7.started && game.started && t7.started > game.started) {
                ImGui::TextColored(kYellow, ICON_FA_TRIANGLE_EXCLAMATION " T7 Patch was started after BO3. Restart BO3 so it's protected from the start.");
            }
            else {
                ImGui::TextColored(kGreen, "BO3 started after T7 Patch. You're protected.");
            }
        }

        const T7Settings& settings = snap.t7Settings;
        if (settings.found) {
            Indent();
            ImGui::TextColored(kGrey, "Friends only: %s   |   Network password: %s   |   Name changer: %s",
                settings.friendsOnly ? "on" : "off", settings.hasPassword ? "set" : "not set", settings.hasName ? "set" : "off");
        }

        ImGui::Spacing();
        Indent();
        if (t7.pid || s_T7Path.empty()) ImGui::BeginDisabled();
        if (ImGui::Button(ICON_FA_SHIELD " Start T7 Patch", ImVec2(220, 35))) {
            StartT7Patch();
        }
        if (t7.pid || s_T7Path.empty()) ImGui::EndDisabled();
        ImGui::SameLine();
        bool busy = s_Launching.load() || game.pid != 0 || s_T7Path.empty();
        if (busy) ImGui::BeginDisabled();
        if (ImGui::Button(ICON_FA_PLAY " Start T7 Patch + BO3", ImVec2(260, 35))) {
            s_Launching = true;
            {
                std::lock_guard<std::mutex> lock(s_LaunchMessageLock);
                s_LaunchMessage = "Starting...";
            }
            std::thread(LaunchWithT7).detach();
        }
        if (busy) ImGui::EndDisabled();

        Indent();
        if (ImGui::Checkbox("Start T7 Patch when the Practice Tool opens", &s_T7AutoStart)) {
            SaveT7Settings();
        }

        std::string launchMessage;
        {
            std::lock_guard<std::mutex> lock(s_LaunchMessageLock);
            launchMessage = s_LaunchMessage;
        }
        if (!launchMessage.empty()) {
            Indent();
            ImGui::Text("%s", launchMessage.c_str());
        }
        else if (!s_T7Message.empty()) {
            Indent();
            ImGui::Text("%s", s_T7Message.c_str());
        }

        ImGui::Spacing();
        ImGui::Separator();
        ImGui::Spacing();
        Indent();
        ImGui::PushTextWrapPos(ImGui::GetContentRegionMax().x - 25.0f);
        ImGui::TextColored(kGrey, "T7 Patch by serious protects BO3 from remote crashes and exploits. Leave it open while you play. "
            "Its settings (friends only, password, name) stay in T7 Patch's own window.");
        ImGui::PopTextWrapPos();
    }
}
