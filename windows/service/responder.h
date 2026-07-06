/*++
    CANARIS — responder userspace Windows : terminaison de processus + snapshot
    VSS. Appelé par le service à réception d'une notification du minifilter.
--*/
#pragma once
#include <windows.h>
#include <string>

namespace canaris {

// Termine le processus suspect (F4.1). Renvoie true si terminé.
bool KillProcess(DWORD pid);

// Déclenche un snapshot VSS du volume (F4.2) via WMI Win32_ShadowCopy::Create.
// `volume` ex: L"C:\\". Renvoie true si la création a réussi.
bool TriggerVssSnapshot(const std::wstring& volume);

// Journalisation horodatée (F4.6) dans le fichier de log + Event Log.
void LogEvent(const std::wstring& line);

} // namespace canaris
