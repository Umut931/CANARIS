/*++
    CANARIS — service userspace Windows.

    Rôle (cahier L2, F4) :
      * se connecte au port de communication du minifilter (\CanarisPort) ;
      * pousse la configuration : dossiers protégés, canaries, whitelist
        (chemins convertis en forme device \Device\HarddiskVolumeN\... pour
        matcher les noms normalisés vus par le driver) ;
      * boucle de réception des notifications kernel -> sur alerte, déclenche le
        responder (kill du processus + snapshot VSS).

    Peut tourner en service SCM (production) ou en mode console (--console, test
    en VM). Le service n'est pas terminable par un process non privilégié (NF8),
    et le port est protégé par ACL admin côté driver (NF9).

    ⚠️ Build en VM Windows (WDK/MSVC). Non compilable dans l'env de dev.
--*/
#include <windows.h>
#include <fltUser.h>
#include <string>
#include <vector>
#include <fstream>

#include "..\\driver\\Canaris.h"
#include "responder.h"

#pragma comment(lib, "FltLib.lib")

static SERVICE_STATUS        gSvcStatus{};
static SERVICE_STATUS_HANDLE gSvcStatusHandle = nullptr;
static HANDLE                gStopEvent = nullptr;
static HANDLE                gPort = INVALID_HANDLE_VALUE;

static const wchar_t* kConfigDir = L"C:\\ProgramData\\Canaris\\";

// Enveloppe reçue via FilterGetMessage (header + payload).
typedef struct _NOTIFY_PACKET {
    FILTER_MESSAGE_HEADER Header;
    CANARIS_NOTIFY_MSG    Msg;
} NOTIFY_PACKET;

typedef struct _REPLY_PACKET {
    FILTER_REPLY_HEADER Header;
    CANARIS_REPLY       Reply;
} REPLY_PACKET;

// ------------------------------------------------------------- utils ------

// Convertit un chemin DOS (C:\...) en chemin device (\Device\HarddiskVolumeN\...)
static std::wstring ToDevicePath(const std::wstring& dos) {
    if (dos.size() < 2 || dos[1] != L':') return dos;
    std::wstring drive = dos.substr(0, 2);       // "C:"
    wchar_t target[MAX_PATH]{};
    if (QueryDosDeviceW(drive.c_str(), target, MAX_PATH) == 0)
        return dos;
    return std::wstring(target) + dos.substr(2); // \Device\HarddiskVolumeN + \...
}

static std::vector<std::wstring> ReadLines(const std::wstring& path) {
    std::vector<std::wstring> out;
    std::wifstream f(path);
    std::wstring line;
    while (std::getline(f, line)) {
        while (!line.empty() && (line.back() == L'\r' || line.back() == L' '))
            line.pop_back();
        if (!line.empty() && line[0] != L'#')
            out.push_back(line);
    }
    return out;
}

static bool SendConfig(CANARIS_CFG_TYPE type, const std::wstring& path,
                       ULONG enforce = 0) {
    CANARIS_CONFIG_MSG cfg{};
    cfg.Type = type;
    cfg.Enforce = enforce;
    if (!path.empty()) {
        std::wstring dev = (type == CanarisCfgAddWhitelist) ? path : ToDevicePath(path);
        size_t bytes = min(dev.size() * sizeof(wchar_t),
                           (size_t)(CANARIS_MAX_PATH * sizeof(wchar_t) - sizeof(wchar_t)));
        memcpy(cfg.Path, dev.c_str(), bytes);
        cfg.PathLength = (USHORT)bytes;
    }
    DWORD returned = 0;
    HRESULT hr = FilterSendMessage(gPort, &cfg, sizeof(cfg), nullptr, 0, &returned);
    return SUCCEEDED(hr);
}

static void PushConfiguration() {
    SendConfig(CanarisCfgClear, L"");
    for (auto& d : ReadLines(std::wstring(kConfigDir) + L"protected_dirs.txt"))
        SendConfig(CanarisCfgAddProtectedDir, d);
    for (auto& c : ReadLines(std::wstring(kConfigDir) + L"canary_files.txt"))
        SendConfig(CanarisCfgAddCanary, c);
    for (auto& w : ReadLines(std::wstring(kConfigDir) + L"whitelist.txt"))
        SendConfig(CanarisCfgAddWhitelist, w);
    SendConfig(CanarisCfgSetEnforce, L"", 1);
    canaris::LogEvent(L"Configuration poussee au minifilter.");
}

// --------------------------------------------------- traitement alerte ----

static void HandleNotification(const CANARIS_NOTIFY_MSG& m) {
    std::wstring path(m.Path, m.PathLength / sizeof(wchar_t));
    std::wstring kind =
        (m.Type == CanarisEvtCanaryHit) ? L"CANARY" :
        (m.Type == CanarisEvtVssDelete) ? L"VSS-DELETE" : L"BLOCKED";
    canaris::LogEvent(L"ALERTE " + kind + L" pid=" + std::to_wstring(m.ProcessId) +
                      L" cible=" + path);

    // Réponse : préserver (VSS) puis tuer (comme côté Linux : snapshot d'abord).
    canaris::TriggerVssSnapshot(L"C:\\");
    canaris::KillProcess(m.ProcessId);
}

// ------------------------------------------------------ boucle de svc -----

static int RunLoop() {
    HRESULT hr = FilterConnectCommunicationPort(CANARIS_PORT_NAME, 0, nullptr, 0,
                                                nullptr, &gPort);
    if (FAILED(hr)) {
        canaris::LogEvent(L"Connexion au port minifilter echouee (driver charge ?)");
        return 1;
    }
    PushConfiguration();

    for (;;) {
        if (gStopEvent && WaitForSingleObject(gStopEvent, 0) == WAIT_OBJECT_0)
            break;

        NOTIFY_PACKET pkt{};
        hr = FilterGetMessage(gPort, &pkt.Header, sizeof(pkt), nullptr);
        if (hr == HRESULT_FROM_WIN32(ERROR_OPERATION_ABORTED))
            break;
        if (FAILED(hr))
            continue;

        HandleNotification(pkt.Msg);

        // Réponse au driver (le blocage est déjà décidé côté kernel ; ici on
        // acquitte simplement).
        REPLY_PACKET reply{};
        reply.Header.MessageId = pkt.Header.MessageId;
        reply.Reply.Block = 1;
        FilterReplyMessage(gPort, &reply.Header, sizeof(reply));
    }

    CloseHandle(gPort);
    gPort = INVALID_HANDLE_VALUE;
    return 0;
}

// --------------------------------------------------------- SCM glue -------

static void ReportStatus(DWORD state, DWORD exitCode = 0, DWORD wait = 0) {
    gSvcStatus.dwCurrentState = state;
    gSvcStatus.dwWin32ExitCode = exitCode;
    gSvcStatus.dwWaitHint = wait;
    gSvcStatus.dwControlsAccepted =
        (state == SERVICE_START_PENDING) ? 0 : SERVICE_ACCEPT_STOP;
    gSvcStatus.dwCheckPoint =
        (state == SERVICE_RUNNING || state == SERVICE_STOPPED) ? 0
        : gSvcStatus.dwCheckPoint + 1;
    SetServiceStatus(gSvcStatusHandle, &gSvcStatus);
}

static void WINAPI SvcCtrlHandler(DWORD ctrl) {
    if (ctrl == SERVICE_CONTROL_STOP || ctrl == SERVICE_CONTROL_SHUTDOWN) {
        ReportStatus(SERVICE_STOP_PENDING);
        if (gStopEvent) SetEvent(gStopEvent);
        if (gPort != INVALID_HANDLE_VALUE) CancelIoEx(gPort, nullptr);
    }
}

static void WINAPI SvcMain(DWORD, LPWSTR*) {
    gSvcStatusHandle = RegisterServiceCtrlHandlerW(L"Canaris", SvcCtrlHandler);
    if (!gSvcStatusHandle) return;
    gSvcStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;

    ReportStatus(SERVICE_START_PENDING, 0, 3000);
    gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    ReportStatus(SERVICE_RUNNING);

    RunLoop();

    ReportStatus(SERVICE_STOPPED);
}

int wmain(int argc, wchar_t** argv) {
    CreateDirectoryW(kConfigDir, nullptr);

    if (argc > 1 && _wcsicmp(argv[1], L"--console") == 0) {
        // Mode test interactif (VM) : Ctrl-C pour arrêter.
        gStopEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        wprintf(L"CANARIS service (console). Connexion au minifilter...\n");
        return RunLoop();
    }

    SERVICE_TABLE_ENTRYW table[] = {
        { (LPWSTR)L"Canaris", SvcMain },
        { nullptr, nullptr }
    };
    if (!StartServiceCtrlDispatcherW(table)) {
        wprintf(L"Lancer avec --console pour le mode test, ou installer le "
                L"service (voir HANDOFF.md).\n");
        return 1;
    }
    return 0;
}
