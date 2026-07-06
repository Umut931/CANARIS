/*++
    CANARIS — prototypes internes partagés entre les fichiers du driver
    (Canaris.c <-> VssGuard.c). Non inclus par l'userspace (types kernel).
--*/
#ifndef CANARIS_INTERNAL_H
#define CANARIS_INTERNAL_H

#include <fltKernel.h>
#include "Canaris.h"

// Notifie le service userspace (défini dans Canaris.c).
VOID CanarisNotify(CANARIS_EVENT_TYPE Type, ULONG Op, PUNICODE_STRING Path);

// VssGuard (défini dans VssGuard.c) : détection de suppression de shadow copies.
NTSTATUS VssGuardRegister(VOID);
VOID     VssGuardUnregister(VOID);

#endif // CANARIS_INTERNAL_H
