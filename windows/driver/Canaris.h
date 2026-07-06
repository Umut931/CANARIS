/*++
    CANARIS — définitions partagées minifilter (Ring 0) <-> service userspace.

    Ce header est inclus par le driver (Canaris.c, VssGuard.c) et par le service
    (service.cpp, responder.cpp). Il décrit :
      * les structures échangées via le port de communication FltMgr ;
      * l'IOCTL de déclenchement VSS ;
      * les constantes (altitude, nom de port, tags de pool).

    Build : VM Windows avec WDK — voir HANDOFF.md [HANDOFF-WIN-WDK]. Non
    compilable dans l'environnement de dev (pas de WDK).
--*/
#ifndef CANARIS_SHARED_H
#define CANARIS_SHARED_H

//
// Nom du port de communication (kernel <-> service userspace).
//
#define CANARIS_PORT_NAME       L"\\CanarisPort"

//
// Altitude du minifilter : plage FSFilter Anti-Virus (320000-329999), choisie
// pour coexister avec Microsoft Defender sans collision (cahier NF12, §5).
// À réserver officiellement auprès de Microsoft pour un déploiement réel.
//
#define CANARIS_ALTITUDE        L"328000"

//
// Tag mémoire pool ('sanC' = Canaris, lu à l'envers dans les dumps).
//
#define CANARIS_POOL_TAG        'sanC'

//
// Longueur max d'un chemin transporté dans un message.
//
#define CANARIS_MAX_PATH        520

//
// Type de message service -> driver (configuration des cibles protégées).
//
typedef enum _CANARIS_CFG_TYPE {
    CanarisCfgAddProtectedDir = 1,   // dossier protégé (sous-arbre)
    CanarisCfgAddCanary       = 2,   // fichier canary (accès = alerte immédiate)
    CanarisCfgAddWhitelist    = 3,   // chemin d'exécutable de confiance
    CanarisCfgClear           = 4,   // vider toutes les listes
    CanarisCfgSetEnforce      = 5,   // 1 = bloquer, 0 = observer
} CANARIS_CFG_TYPE;

//
// Message service -> driver : ajoute/retire une cible.
//
typedef struct _CANARIS_CONFIG_MSG {
    CANARIS_CFG_TYPE Type;
    ULONG            Enforce;                 // pour CanarisCfgSetEnforce
    USHORT           PathLength;              // en octets (WCHAR)
    WCHAR            Path[CANARIS_MAX_PATH];  // chemin normalisé (\Device\...)
} CANARIS_CONFIG_MSG, *PCANARIS_CONFIG_MSG;

//
// Type d'événement driver -> service (notification).
//
typedef enum _CANARIS_EVENT_TYPE {
    CanarisEvtCanaryHit   = 1,   // accès à un canary
    CanarisEvtBlocked     = 2,   // opération bloquée (STATUS_ACCESS_DENIED)
    CanarisEvtVssDelete   = 3,   // tentative de suppression de shadow copies (VssGuard)
} CANARIS_EVENT_TYPE;

//
// Notification driver -> service : demande kill + réponse.
//
typedef struct _CANARIS_NOTIFY_MSG {
    CANARIS_EVENT_TYPE Type;
    ULONG              ProcessId;             // PID responsable
    ULONG              Operation;             // IRP_MJ_* ou code interne
    USHORT             PathLength;            // en octets
    WCHAR              Path[CANARIS_MAX_PATH];// cible
} CANARIS_NOTIFY_MSG, *PCANARIS_NOTIFY_MSG;

//
// Réponse du service au driver (autoriser/refuser) — mode synchrone optionnel.
//
typedef struct _CANARIS_REPLY {
    ULONG Block;   // 1 = refuser l'opération, 0 = autoriser
} CANARIS_REPLY, *PCANARIS_REPLY;

//
// IOCTL de déclenchement d'un snapshot VSS (service -> composant VSS userspace,
// cahier F4.2). Défini ici pour partage.
//
#define CANARIS_DEVICE_TYPE   0x8000
#define IOCTL_CANARIS_TRIGGER_VSS \
    CTL_CODE(CANARIS_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#endif // CANARIS_SHARED_H
