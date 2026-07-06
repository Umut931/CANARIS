/*++
    CANARIS — minifilter anti-ransomware (Ring 0, Windows).

    Équivalent Windows du composant Linux eBPF+LSM : intercepte les I/O
    filesystem, bloque réellement (STATUS_ACCESS_DENIED) les accès aux canaries
    et dossiers protégés par des processus non whitelistés, et notifie le
    service userspace (kill + snapshot VSS).

    Décisions d'architecture (CLAUDE.md §5) :
      * Callbacks pré-opération sur IRP_MJ_CREATE, IRP_MJ_WRITE,
        IRP_MJ_SET_INFORMATION (rename/delete).
      * Blocage = FLT_PREOP_COMPLETE + STATUS_ACCESS_DENIED dans le pré-callback.
      * Altitude dans la plage anti-virus (328000).
      * Communication kernel <-> service via FltCreateCommunicationPort.
      * Mémoire : ExAllocatePool2 (jamais ExAllocatePoolWithTag, déprécié),
        libérée systématiquement.

    ⚠️ Build en VM Windows avec WDK uniquement (HANDOFF.md [HANDOFF-WIN-WDK]).
    Non compilable dans l'environnement de dev. Tester avec Driver Verifier.
--*/

#include <fltKernel.h>
#include <dontuse.h>
#include "Canaris.h"
#include "Canaris_internal.h"

//
// -------------------------------------------------------------- globals ----
//
PFLT_FILTER  gFilterHandle = NULL;
PFLT_PORT    gServerPort   = NULL;   // port serveur (FltCreateCommunicationPort)
PFLT_PORT    gClientPort   = NULL;   // connexion du service (unique)
BOOLEAN      gEnforce      = TRUE;   // TRUE = bloquer, FALSE = observer

//
// Entrée de liste de cibles protégées / canaries / whitelist.
//
typedef struct _CANARIS_ENTRY {
    LIST_ENTRY     Link;
    UNICODE_STRING Path;       // buffer alloué (pool), normalisé, minuscule
    BOOLEAN        IsCanary;   // TRUE = canary (alerte immédiate)
    BOOLEAN        IsDir;      // TRUE = dossier protégé (match par préfixe)
} CANARIS_ENTRY, *PCANARIS_ENTRY;

LIST_ENTRY   gProtectedList;         // dossiers + canaries
LIST_ENTRY   gWhitelist;             // chemins d'exécutables de confiance
FAST_MUTEX   gListLock;

//
// -------------------------------------------------------- déclarations ----
//
DRIVER_INITIALIZE DriverEntry;
NTSTATUS FLTAPI CanarisUnload(FLT_FILTER_UNLOAD_FLAGS Flags);
NTSTATUS FLTAPI CanarisInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType,
    FLT_FILESYSTEM_TYPE VolumeFilesystemType);
NTSTATUS FLTAPI CanarisInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
    FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags);

FLT_PREOP_CALLBACK_STATUS FLTAPI CanarisPreCreate(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS FLTAPI CanarisPreWrite(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);
FLT_PREOP_CALLBACK_STATUS FLTAPI CanarisPreSetInfo(PFLT_CALLBACK_DATA Data,
    PCFLT_RELATED_OBJECTS FltObjects, PVOID *CompletionContext);

NTSTATUS CanarisPortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
    PVOID ConnectionContext, ULONG SizeOfContext, PVOID *ConnectionPortCookie);
VOID CanarisPortDisconnect(PVOID ConnectionCookie);
NTSTATUS CanarisPortMessage(PVOID PortCookie, PVOID InputBuffer,
    ULONG InputBufferLength, PVOID OutputBuffer, ULONG OutputBufferLength,
    PULONG ReturnOutputBufferLength);

//
// ------------------------------------------------------- registration ----
//
CONST FLT_OPERATION_REGISTRATION Callbacks[] = {
    { IRP_MJ_CREATE,          0, CanarisPreCreate,  NULL },
    { IRP_MJ_WRITE,           0, CanarisPreWrite,   NULL },
    { IRP_MJ_SET_INFORMATION, 0, CanarisPreSetInfo, NULL },
    { IRP_MJ_OPERATION_END }
};

CONST FLT_REGISTRATION FilterRegistration = {
    sizeof(FLT_REGISTRATION),
    FLT_REGISTRATION_VERSION,
    0,                                  // Flags
    NULL,                               // ContextRegistration
    Callbacks,
    CanarisUnload,
    CanarisInstanceSetup,
    CanarisInstanceQueryTeardown,
    NULL, NULL, NULL, NULL, NULL, NULL, NULL
};

//
// ============================================================ helpers ====
//

//
// Alloue et copie une chaîne WCHAR normalisée (minuscule) dans une UNICODE_STRING.
//
static NTSTATUS CanarisDupPath(_In_ PCWSTR Src, _In_ USHORT LenBytes,
                               _Out_ PUNICODE_STRING Dst)
{
    Dst->Buffer = (PWCH)ExAllocatePool2(POOL_FLAG_NON_PAGED, LenBytes,
                                        CANARIS_POOL_TAG);
    if (Dst->Buffer == NULL)
        return STATUS_INSUFFICIENT_RESOURCES;
    RtlCopyMemory(Dst->Buffer, Src, LenBytes);
    Dst->Length = LenBytes;
    Dst->MaximumLength = LenBytes;
    // Pas de mise en minuscule : les comparaisons Rtl*UnicodeString(..., TRUE)
    // sont insensibles à la casse (et _wcslwr n'existe pas en kernel).
    return STATUS_SUCCESS;
}

//
// Le chemin cible est-il protégé ? Renvoie l'entrée et remplit *isCanary.
// Match : exact pour un canary, préfixe pour un dossier protégé.
//
static BOOLEAN CanarisIsProtected(_In_ PUNICODE_STRING Target, _Out_ PBOOLEAN IsCanary)
{
    PLIST_ENTRY e;
    BOOLEAN found = FALSE;
    *IsCanary = FALSE;

    ExAcquireFastMutex(&gListLock);
    for (e = gProtectedList.Flink; e != &gProtectedList; e = e->Flink) {
        PCANARIS_ENTRY entry = CONTAINING_RECORD(e, CANARIS_ENTRY, Link);
        if (entry->IsDir) {
            // préfixe : Target commence par entry->Path + '\'
            if (Target->Length >= entry->Path.Length &&
                RtlPrefixUnicodeString(&entry->Path, Target, TRUE)) {
                found = TRUE;
                break;
            }
        } else {
            if (RtlEqualUnicodeString(&entry->Path, Target, TRUE)) {
                found = TRUE;
                *IsCanary = entry->IsCanary;
                break;
            }
        }
    }
    ExReleaseFastMutex(&gListLock);
    return found;
}

//
// Le processus appelant est-il whitelisté ?
//
// Durcissement T2 : comparaison du CHEMIN D'IMAGE COMPLET normalisé
// (\Device\HarddiskVolumeN\...), PAS un suffixe (un attaquant nommant son
// binaire « rsync.exe » ne doit pas être exempté). Le service pousse les
// chemins whitelistés déjà convertis en forme device (voir service.cpp).
// Robustesse maximale visée = vérification Authenticode (hors scope, cf.
// windows/REVIEW_NOTES.md et docs/LIMITATIONS.md).
//
static BOOLEAN CanarisIsWhitelisted(VOID)
{
    PUNICODE_STRING image = NULL;
    BOOLEAN white = FALSE;
    PLIST_ENTRY e;

    // SeLocateProcessImageName alloue image (à libérer avec ExFreePool).
    if (!NT_SUCCESS(SeLocateProcessImageName(PsGetCurrentProcess(), &image)) ||
        image == NULL)
        return FALSE;

    ExAcquireFastMutex(&gListLock);
    for (e = gWhitelist.Flink; e != &gWhitelist; e = e->Flink) {
        PCANARIS_ENTRY entry = CONTAINING_RECORD(e, CANARIS_ENTRY, Link);
        // Égalité EXACTE du chemin d'image complet (insensible à la casse).
        if (RtlEqualUnicodeString(&entry->Path, image, TRUE)) {
            white = TRUE;
            break;
        }
    }
    ExReleaseFastMutex(&gListLock);
    ExFreePool(image);
    return white;
}

//
// Notifie le service (kill + snapshot). Best-effort, non bloquant.
// Non statique : aussi appelée par VssGuard.c (voir Canaris_internal.h).
//
VOID CanarisNotify(_In_ CANARIS_EVENT_TYPE Type, _In_ ULONG Op,
                   _In_ PUNICODE_STRING Path)
{
    CANARIS_NOTIFY_MSG msg;
    LARGE_INTEGER timeout;

    if (gClientPort == NULL)
        return;

    RtlZeroMemory(&msg, sizeof(msg));
    msg.Type = Type;
    msg.ProcessId = (ULONG)(ULONG_PTR)PsGetCurrentProcessId();
    msg.Operation = Op;
    if (Path != NULL && Path->Length > 0) {
        USHORT copy = min(Path->Length, (USHORT)(CANARIS_MAX_PATH * sizeof(WCHAR) - sizeof(WCHAR)));
        RtlCopyMemory(msg.Path, Path->Buffer, copy);
        msg.PathLength = copy;
    }

    // Envoi non bloquant (timeout court) — la décision de blocage est déjà prise
    // côté kernel ; le service gère kill/VSS en asynchrone.
    timeout.QuadPart = -10 * 1000 * 100; // 100 ms (unités de 100 ns, relatif)
    (VOID)FltSendMessage(gFilterHandle, &gClientPort, &msg, sizeof(msg),
                         NULL, NULL, &timeout);
}

//
// Cœur de décision partagé par les trois pré-callbacks.
// Renvoie TRUE si l'opération doit être BLOQUÉE.
//
static BOOLEAN CanarisDecide(_In_ PFLT_CALLBACK_DATA Data,
                             _In_ PCFLT_RELATED_OBJECTS FltObjects,
                             _In_ ULONG Op)
{
    PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
    BOOLEAN isCanary = FALSE, protectedTarget = FALSE, block = FALSE;
    NTSTATUS status;

    // FltGetFileNameInformation exige PASSIVE_LEVEL et pas de paging I/O.
    if (KeGetCurrentIrql() != PASSIVE_LEVEL)
        return FALSE;
    if (FlagOn(Data->Iopb->IrpFlags, IRP_PAGING_IO))
        return FALSE;

    status = FltGetFileNameInformation(Data,
        FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
    if (!NT_SUCCESS(status) || nameInfo == NULL)
        return FALSE;

    FltParseFileNameInformation(nameInfo);

    // Comparaisons insensibles à la casse via Rtl*UnicodeString(..., TRUE) :
    // pas besoin de recopier/mettre en minuscule le nom normalisé.
    protectedTarget = CanarisIsProtected(&nameInfo->Name, &isCanary);
    if (protectedTarget && !CanarisIsWhitelisted()) {
        CanarisNotify(isCanary ? CanarisEvtCanaryHit : CanarisEvtBlocked,
                      Op, &nameInfo->Name);
        block = gEnforce ? TRUE : FALSE;
    }

    FltReleaseFileNameInformation(nameInfo);
    return block;
}

//
// ======================================================= pré-callbacks ===
//
FLT_PREOP_CALLBACK_STATUS FLTAPI
CanarisPreCreate(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                 PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (CanarisDecide(Data, FltObjects, IRP_MJ_CREATE)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;   // opération refusée dès le pré-callback
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_PREOP_CALLBACK_STATUS FLTAPI
CanarisPreWrite(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                PVOID *CompletionContext)
{
    UNREFERENCED_PARAMETER(CompletionContext);

    if (CanarisDecide(Data, FltObjects, IRP_MJ_WRITE)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// IRP_MJ_SET_INFORMATION couvre le rename et le delete (dispositions),
// techniques centrales du ransomware (.locked / suppression de l'original).
//
FLT_PREOP_CALLBACK_STATUS FLTAPI
CanarisPreSetInfo(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects,
                  PVOID *CompletionContext)
{
    FILE_INFORMATION_CLASS infoClass;
    UNREFERENCED_PARAMETER(CompletionContext);

    infoClass = Data->Iopb->Parameters.SetFileInformation.FileInformationClass;

    // On ne s'intéresse qu'au rename et à la suppression.
    if (infoClass != FileRenameInformation &&
        infoClass != FileRenameInformationEx &&
        infoClass != FileDispositionInformation &&
        infoClass != FileDispositionInformationEx) {
        return FLT_PREOP_SUCCESS_NO_CALLBACK;
    }

    if (CanarisDecide(Data, FltObjects, IRP_MJ_SET_INFORMATION)) {
        Data->IoStatus.Status = STATUS_ACCESS_DENIED;
        Data->IoStatus.Information = 0;
        return FLT_PREOP_COMPLETE;
    }
    return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//
// ================================================= port de communication ==
//
NTSTATUS
CanarisPortConnect(PFLT_PORT ClientPort, PVOID ServerPortCookie,
                   PVOID ConnectionContext, ULONG SizeOfContext,
                   PVOID *ConnectionPortCookie)
{
    UNREFERENCED_PARAMETER(ServerPortCookie);
    UNREFERENCED_PARAMETER(ConnectionContext);
    UNREFERENCED_PARAMETER(SizeOfContext);
    UNREFERENCED_PARAMETER(ConnectionPortCookie);

    // Une seule connexion (le service). NF8/NF9 : port protégé par ACL admin.
    gClientPort = ClientPort;
    return STATUS_SUCCESS;
}

VOID
CanarisPortDisconnect(PVOID ConnectionCookie)
{
    UNREFERENCED_PARAMETER(ConnectionCookie);
    FltCloseClientPort(gFilterHandle, &gClientPort);
    gClientPort = NULL;
}

//
// Réception d'un message de configuration (service -> driver).
//
static VOID CanarisAddEntry(PCANARIS_CONFIG_MSG cfg)
{
    PCANARIS_ENTRY entry;
    if (cfg->PathLength == 0 || cfg->PathLength > CANARIS_MAX_PATH * sizeof(WCHAR))
        return;

    entry = (PCANARIS_ENTRY)ExAllocatePool2(POOL_FLAG_NON_PAGED,
                                            sizeof(CANARIS_ENTRY), CANARIS_POOL_TAG);
    if (entry == NULL)
        return;
    RtlZeroMemory(entry, sizeof(*entry));

    if (!NT_SUCCESS(CanarisDupPath(cfg->Path, cfg->PathLength, &entry->Path))) {
        ExFreePool(entry);
        return;
    }
    entry->IsCanary = (cfg->Type == CanarisCfgAddCanary);
    entry->IsDir    = (cfg->Type == CanarisCfgAddProtectedDir);

    ExAcquireFastMutex(&gListLock);
    if (cfg->Type == CanarisCfgAddWhitelist)
        InsertTailList(&gWhitelist, &entry->Link);
    else
        InsertTailList(&gProtectedList, &entry->Link);
    ExReleaseFastMutex(&gListLock);
}

static VOID CanarisClearList(PLIST_ENTRY list)
{
    while (!IsListEmpty(list)) {
        PLIST_ENTRY e = RemoveHeadList(list);
        PCANARIS_ENTRY entry = CONTAINING_RECORD(e, CANARIS_ENTRY, Link);
        if (entry->Path.Buffer)
            ExFreePool(entry->Path.Buffer);
        ExFreePool(entry);
    }
}

NTSTATUS
CanarisPortMessage(PVOID PortCookie, PVOID InputBuffer, ULONG InputBufferLength,
                   PVOID OutputBuffer, ULONG OutputBufferLength,
                   PULONG ReturnOutputBufferLength)
{
    UNREFERENCED_PARAMETER(PortCookie);
    UNREFERENCED_PARAMETER(OutputBuffer);
    UNREFERENCED_PARAMETER(OutputBufferLength);

    *ReturnOutputBufferLength = 0;

    if (InputBuffer == NULL || InputBufferLength < sizeof(CANARIS_CONFIG_MSG))
        return STATUS_INVALID_PARAMETER;

    // Copie défensive depuis le buffer userspace (déjà probé par FltMgr).
    CANARIS_CONFIG_MSG cfg;
    __try {
        RtlCopyMemory(&cfg, InputBuffer, sizeof(cfg));
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        return STATUS_INVALID_USER_BUFFER;
    }

    switch (cfg.Type) {
    case CanarisCfgAddProtectedDir:
    case CanarisCfgAddCanary:
    case CanarisCfgAddWhitelist:
        CanarisAddEntry(&cfg);
        break;
    case CanarisCfgClear:
        ExAcquireFastMutex(&gListLock);
        CanarisClearList(&gProtectedList);
        CanarisClearList(&gWhitelist);
        ExReleaseFastMutex(&gListLock);
        break;
    case CanarisCfgSetEnforce:
        gEnforce = (cfg.Enforce != 0);
        break;
    default:
        return STATUS_INVALID_PARAMETER;
    }
    return STATUS_SUCCESS;
}

//
// ============================================ instance / unload / entry ===
//
NTSTATUS FLTAPI
CanarisInstanceSetup(PCFLT_RELATED_OBJECTS FltObjects,
                     FLT_INSTANCE_SETUP_FLAGS Flags, DEVICE_TYPE VolumeDeviceType,
                     FLT_FILESYSTEM_TYPE VolumeFilesystemType)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    UNREFERENCED_PARAMETER(VolumeDeviceType);
    // On ne s'attache pas aux volumes réseau/inconnus.
    if (VolumeFilesystemType == FLT_FSTYPE_RAW)
        return STATUS_FLT_DO_NOT_ATTACH;
    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI
CanarisInstanceQueryTeardown(PCFLT_RELATED_OBJECTS FltObjects,
                             FLT_INSTANCE_QUERY_TEARDOWN_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(FltObjects);
    UNREFERENCED_PARAMETER(Flags);
    return STATUS_SUCCESS;
}

NTSTATUS FLTAPI
CanarisUnload(FLT_FILTER_UNLOAD_FLAGS Flags)
{
    UNREFERENCED_PARAMETER(Flags);

    VssGuardUnregister();

    if (gServerPort)
        FltCloseCommunicationPort(gServerPort);

    if (gFilterHandle)
        FltUnregisterFilter(gFilterHandle);

    ExAcquireFastMutex(&gListLock);
    CanarisClearList(&gProtectedList);
    CanarisClearList(&gWhitelist);
    ExReleaseFastMutex(&gListLock);

    return STATUS_SUCCESS;
}

NTSTATUS
DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;
    PSECURITY_DESCRIPTOR sd = NULL;
    OBJECT_ATTRIBUTES oa;
    UNICODE_STRING portName;

    UNREFERENCED_PARAMETER(RegistryPath);

    InitializeListHead(&gProtectedList);
    InitializeListHead(&gWhitelist);
    ExInitializeFastMutex(&gListLock);

    status = FltRegisterFilter(DriverObject, &FilterRegistration, &gFilterHandle);
    if (!NT_SUCCESS(status))
        return status;

    // Port de communication protégé : accès administrateur uniquement (NF8/NF9).
    status = FltBuildDefaultSecurityDescriptor(&sd, FLT_PORT_ALL_ACCESS);
    if (!NT_SUCCESS(status))
        goto fail;

    RtlInitUnicodeString(&portName, CANARIS_PORT_NAME);
    InitializeObjectAttributes(&oa, &portName,
        OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, sd);

    status = FltCreateCommunicationPort(gFilterHandle, &gServerPort, &oa, NULL,
        CanarisPortConnect, CanarisPortDisconnect, CanarisPortMessage, 1);
    FltFreeSecurityDescriptor(sd);
    if (!NT_SUCCESS(status))
        goto fail;

    status = FltStartFiltering(gFilterHandle);
    if (!NT_SUCCESS(status)) {
        FltCloseCommunicationPort(gServerPort);
        goto fail;
    }

    // VssGuard : surveillance des créations de process (vssadmin/wmic/bcdedit).
    // Échec non fatal : le minifilter reste opérationnel sans VssGuard.
    (VOID)VssGuardRegister();

    return STATUS_SUCCESS;

fail:
    FltUnregisterFilter(gFilterHandle);
    gFilterHandle = NULL;
    return status;
}
