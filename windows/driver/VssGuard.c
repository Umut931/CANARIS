/*++
    CANARIS — VssGuard : détection de la suppression des sauvegardes (cahier F5).

    Les ransomwares suppriment les shadow copies AVANT de chiffrer, pour empêcher
    toute restauration (CLAUDE.md §2.4). Ce comportement NE déclenche PAS le
    seuil d'I/O : il faut une détection DÉDIÉE. VssGuard surveille les créations
    de processus via PsSetCreateProcessNotifyRoutineEx et reconnaît les commandes
    destructrices (vssadmin/wmic/bcdedit/wbadmin/powershell) — voir
    vssguard_rules.h (logique portable, testée unitairement).

    Sur détection : alerte PRIORITÉ MAXIMALE immédiate au service (kill + VSS),
    indépendante du seuil d'I/O, ET blocage de la création du processus en
    positionnant CreateInfo->CreationStatus = STATUS_ACCESS_DENIED (F5.2).

    ⚠️ Build en VM Windows (WDK). Non compilable dans l'env de dev. La logique de
    matching (vssguard_rules.h) est, elle, compilée et testée avec gcc
    (tests/ctest/test_vssguard.c) et reflétée en Python.
--*/
#include <fltKernel.h>
#include "Canaris.h"
#include "Canaris_internal.h"
#include "vssguard_rules.h"

extern BOOLEAN gEnforce;

//
// Callback de création/terminaison de processus.
//
static VOID
VssGuardCreateProcessNotify(_Inout_ PEPROCESS Process, _In_ HANDLE ProcessId,
                            _Inout_opt_ PPS_CREATE_NOTIFY_INFO CreateInfo)
{
    UNREFERENCED_PARAMETER(Process);

    // CreateInfo == NULL => terminaison de processus : rien à faire.
    if (CreateInfo == NULL)
        return;

    // Les UNICODE_STRING ne sont PAS garanties nul-terminées : on en fait des
    // copies bornées et nul-terminées sur la pile (évite tout dépassement de
    // lecture dans le classifieur qui s'appuie sur wcslen).
    #define VG_IMG_MAX  260
    #define VG_CMD_MAX  1024
    WCHAR image[VG_IMG_MAX];
    WCHAR cmd[VG_CMD_MAX];
    image[0] = L'\0';
    cmd[0]   = L'\0';

    if (CreateInfo->ImageFileName && CreateInfo->ImageFileName->Buffer) {
        USHORT n = CreateInfo->ImageFileName->Length / sizeof(WCHAR);
        if (n > VG_IMG_MAX - 1) n = VG_IMG_MAX - 1;
        RtlCopyMemory(image, CreateInfo->ImageFileName->Buffer, n * sizeof(WCHAR));
        image[n] = L'\0';
    }
    if (CreateInfo->CommandLine && CreateInfo->CommandLine->Buffer) {
        USHORT n = CreateInfo->CommandLine->Length / sizeof(WCHAR);
        if (n > VG_CMD_MAX - 1) n = VG_CMD_MAX - 1;
        RtlCopyMemory(cmd, CreateInfo->CommandLine->Buffer, n * sizeof(WCHAR));
        cmd[n] = L'\0';
    }

    vg_verdict v = vssguard_classify(image, cmd);
    if (v == VG_NONE)
        return;

    // Alerte immédiate au service (priorité maximale, hors seuil d'I/O).
    UNICODE_STRING target;
    if (CreateInfo->CommandLine)
        target = *CreateInfo->CommandLine;
    else
        RtlInitUnicodeString(&target, L"(vss)");

    CanarisNotify(CanarisEvtVssDelete, (ULONG)v, &target);

    // Blocage : empêche la création du processus destructeur (F5.2).
    if (gEnforce)
        CreateInfo->CreationStatus = STATUS_ACCESS_DENIED;

    DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL,
               "CANARIS VssGuard: bloque pid=%p (%s)\n",
               ProcessId, vssguard_reason(v));
}

NTSTATUS VssGuardRegister(VOID)
{
    // TRUE en dernier paramètre = version Ex avec possibilité de refuser la
    // création (CreationStatus). Nécessite un driver signé (Test Signing en VM).
    return PsSetCreateProcessNotifyRoutineEx(VssGuardCreateProcessNotify, FALSE);
}

VOID VssGuardUnregister(VOID)
{
    PsSetCreateProcessNotifyRoutineEx(VssGuardCreateProcessNotify, TRUE);
}
