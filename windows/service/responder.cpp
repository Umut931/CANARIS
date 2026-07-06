/*++
    CANARIS — implémentation du responder userspace Windows.

    * KillProcess       : OpenProcess(PROCESS_TERMINATE) + TerminateProcess.
    * TriggerVssSnapshot: création d'une shadow copy via WMI Win32_ShadowCopy
                          ::Create — c'est la voie programmatique standard sous
                          Windows (une version « production » utiliserait
                          directement IVssBackupComponents, plus riche mais bien
                          plus verbeuse ; documenté dans docs/LIMITATIONS.md).
    * LogEvent          : journalisation fichier + Event Log.

    ⚠️ Build en VM Windows (WDK/MSVC). Non compilable dans l'env de dev.
--*/
#include "responder.h"

#include <comdef.h>
#include <Wbemidl.h>
#include <fstream>
#include <chrono>
#include <iomanip>
#include <sstream>

#pragma comment(lib, "wbemuuid.lib")

namespace canaris {

void LogEvent(const std::wstring& line) {
    // Horodatage ISO
    auto now = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(now);
    std::tm tm{};
    localtime_s(&tm, &t);
    std::wstringstream ss;
    ss << std::put_time(&tm, L"%Y-%m-%dT%H:%M:%S") << L" " << line;

    // Fichier (à côté du binaire du service)
    std::wofstream f(L"C:\\ProgramData\\Canaris\\canaris_events.log",
                     std::ios::app);
    if (f) f << ss.str() << L"\n";

    OutputDebugStringW((ss.str() + L"\n").c_str());
}

bool KillProcess(DWORD pid) {
    if (pid == 0) return false;
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (h == nullptr) {
        LogEvent(L"KILL echec: OpenProcess pid=" + std::to_wstring(pid));
        return false;
    }
    BOOL ok = TerminateProcess(h, 1);
    CloseHandle(h);
    LogEvent((ok ? L"KILL ok pid=" : L"KILL echec pid=") + std::to_wstring(pid));
    return ok == TRUE;
}

//
// Création d'une shadow copy via WMI (root\cimv2, Win32_ShadowCopy::Create).
//
bool TriggerVssSnapshot(const std::wstring& volume) {
    HRESULT hr;
    bool result = false;

    hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
    bool didInit = SUCCEEDED(hr);
    if (hr == RPC_E_CHANGED_MODE) didInit = false; // déjà initialisé autrement

    // Sécurité COM par défaut (peut échouer si déjà appelée — non fatal).
    CoInitializeSecurity(nullptr, -1, nullptr, nullptr,
        RPC_C_AUTHN_LEVEL_DEFAULT, RPC_C_IMP_LEVEL_IMPERSONATE,
        nullptr, EOAC_NONE, nullptr);

    IWbemLocator*  loc = nullptr;
    IWbemServices* svc = nullptr;
    IWbemClassObject* cls = nullptr;
    IWbemClassObject* inParamsDef = nullptr;
    IWbemClassObject* inParams = nullptr;
    IWbemClassObject* outParams = nullptr;

    hr = CoCreateInstance(CLSID_WbemLocator, nullptr, CLSCTX_INPROC_SERVER,
                          IID_IWbemLocator, (void**)&loc);
    if (FAILED(hr)) goto done;

    hr = loc->ConnectServer(_bstr_t(L"ROOT\\CIMV2"), nullptr, nullptr, nullptr,
                            0, nullptr, nullptr, &svc);
    if (FAILED(hr)) goto done;

    hr = CoSetProxyBlanket(svc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, nullptr,
        RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, nullptr, EOAC_NONE);
    if (FAILED(hr)) goto done;

    hr = svc->GetObjectW(_bstr_t(L"Win32_ShadowCopy"), 0, nullptr, &cls, nullptr);
    if (FAILED(hr)) goto done;

    hr = cls->GetMethod(L"Create", 0, &inParamsDef, nullptr);
    if (FAILED(hr)) goto done;

    hr = inParamsDef->SpawnInstance(0, &inParams);
    if (FAILED(hr)) goto done;

    {
        VARIANT v; VariantInit(&v);
        v.vt = VT_BSTR; v.bstrVal = SysAllocString(volume.c_str());
        inParams->Put(L"Volume", 0, &v, 0);
        VariantClear(&v);

        v.vt = VT_BSTR; v.bstrVal = SysAllocString(L"ClientAccessible");
        inParams->Put(L"Context", 0, &v, 0);
        VariantClear(&v);
    }

    hr = svc->ExecMethod(_bstr_t(L"Win32_ShadowCopy"), _bstr_t(L"Create"), 0,
                         nullptr, inParams, &outParams, nullptr);
    if (SUCCEEDED(hr) && outParams) {
        VARIANT ret; VariantInit(&ret);
        if (SUCCEEDED(outParams->Get(L"ReturnValue", 0, &ret, nullptr, nullptr)))
            result = (ret.uintVal == 0);   // 0 = succès
        VariantClear(&ret);
    }
    LogEvent(result ? L"VSS snapshot cree (" + volume + L")"
                    : L"VSS snapshot echec (" + volume + L")");

done:
    if (outParams)    outParams->Release();
    if (inParams)     inParams->Release();
    if (inParamsDef)  inParamsDef->Release();
    if (cls)          cls->Release();
    if (svc)          svc->Release();
    if (loc)          loc->Release();
    if (didInit)      CoUninitialize();
    return result;
}

} // namespace canaris
