/*++
    CANARIS — règles de détection VssGuard (portable, sans dépendance WDK).

    Reconnaît les commandes de destruction de sauvegardes que les ransomwares
    lancent AVANT de chiffrer (cahier F5.1, CLAUDE.md §2.4) :
      vssadmin delete shadows / resize shadowstorage,
      wmic shadowcopy delete, bcdedit (désactivation de la récupération),
      wbadmin delete catalog/systemstatebackup,
      PowerShell Win32_Shadowcopy Delete/Remove.

    Ce header ne dépend QUE du CRT large-char portable (towlower) : il compile
    et se teste avec gcc (wchar_t 4 octets) ET dans le driver Windows (wchar_t
    2 octets). Il est inclus par windows/driver/VssGuard.c et par le test
    tests/ctest/test_vssguard.c. La logique est aussi reflétée en Python
    (common/vssguard_rules.py) pour tests/test_vssguard_parsing.py.
--*/
#ifndef CANARIS_VSSGUARD_RULES_H
#define CANARIS_VSSGUARD_RULES_H

#include <wchar.h>
#include <wctype.h>

typedef enum {
    VG_NONE = 0,
    VG_VSSADMIN_DELETE,     /* vssadmin delete shadows            */
    VG_VSSADMIN_RESIZE,     /* vssadmin resize shadowstorage (évince) */
    VG_WMIC_SHADOW_DELETE,  /* wmic shadowcopy delete             */
    VG_BCDEDIT_RECOVERY,    /* bcdedit désactive la récupération  */
    VG_WBADMIN_DELETE,      /* wbadmin delete catalog/backup      */
    VG_PS_SHADOW_DELETE,    /* powershell Win32_Shadowcopy delete */
} vg_verdict;

/* Recherche de sous-chaîne insensible à la casse (large chars, portable). */
static int vg_contains_ci(const wchar_t *hay, const wchar_t *needle)
{
    if (!hay || !needle || !needle[0])
        return 0;
    for (const wchar_t *h = hay; *h; ++h) {
        const wchar_t *a = h, *b = needle;
        while (*a && *b && towlower((wint_t)*a) == towlower((wint_t)*b)) {
            ++a; ++b;
        }
        if (!*b)
            return 1;
    }
    return 0;
}

/* Le nom d'image se termine-t-il par `suffix` (insensible à la casse) ? */
static int vg_image_is(const wchar_t *image, const wchar_t *suffix)
{
    if (!image || !suffix)
        return 0;
    size_t li = wcslen(image), ls = wcslen(suffix);
    if (ls > li)
        return 0;
    const wchar_t *tail = image + (li - ls);
    for (size_t i = 0; i < ls; ++i)
        if (towlower((wint_t)tail[i]) != towlower((wint_t)suffix[i]))
            return 0;
    return 1;
}

/*
 * Classe une création de processus. `image` = chemin/nom de l'exécutable,
 * `cmdline` = ligne de commande complète. Renvoie le verdict (VG_NONE si rien).
 */
static vg_verdict vssguard_classify(const wchar_t *image, const wchar_t *cmdline)
{
    if (!cmdline)
        cmdline = L"";

    if (vg_image_is(image, L"vssadmin.exe") || vg_contains_ci(cmdline, L"vssadmin")) {
        if (vg_contains_ci(cmdline, L"delete") && vg_contains_ci(cmdline, L"shadow"))
            return VG_VSSADMIN_DELETE;
        if (vg_contains_ci(cmdline, L"resize") && vg_contains_ci(cmdline, L"shadowstorage"))
            return VG_VSSADMIN_RESIZE;
    }
    if (vg_image_is(image, L"wmic.exe") || vg_contains_ci(cmdline, L"wmic")) {
        if (vg_contains_ci(cmdline, L"shadowcopy") && vg_contains_ci(cmdline, L"delete"))
            return VG_WMIC_SHADOW_DELETE;
    }
    if (vg_image_is(image, L"bcdedit.exe") || vg_contains_ci(cmdline, L"bcdedit")) {
        if (vg_contains_ci(cmdline, L"recoveryenabled") && vg_contains_ci(cmdline, L"no"))
            return VG_BCDEDIT_RECOVERY;
        if (vg_contains_ci(cmdline, L"bootstatuspolicy") &&
            vg_contains_ci(cmdline, L"ignoreallfailures"))
            return VG_BCDEDIT_RECOVERY;
    }
    if (vg_image_is(image, L"wbadmin.exe") || vg_contains_ci(cmdline, L"wbadmin")) {
        if (vg_contains_ci(cmdline, L"delete") &&
            (vg_contains_ci(cmdline, L"catalog") ||
             vg_contains_ci(cmdline, L"systemstatebackup") ||
             vg_contains_ci(cmdline, L"backup")))
            return VG_WBADMIN_DELETE;
    }
    if (vg_image_is(image, L"powershell.exe") || vg_image_is(image, L"pwsh.exe") ||
        vg_contains_ci(cmdline, L"powershell")) {
        if (vg_contains_ci(cmdline, L"win32_shadowcopy") &&
            (vg_contains_ci(cmdline, L"delete") || vg_contains_ci(cmdline, L"remove")))
            return VG_PS_SHADOW_DELETE;
    }
    return VG_NONE;
}

static const char *vssguard_reason(vg_verdict v)
{
    switch (v) {
    case VG_VSSADMIN_DELETE:    return "vssadmin delete shadows";
    case VG_VSSADMIN_RESIZE:    return "vssadmin resize shadowstorage";
    case VG_WMIC_SHADOW_DELETE: return "wmic shadowcopy delete";
    case VG_BCDEDIT_RECOVERY:   return "bcdedit disable recovery";
    case VG_WBADMIN_DELETE:     return "wbadmin delete backup";
    case VG_PS_SHADOW_DELETE:   return "powershell shadowcopy delete";
    default:                    return "none";
    }
}

#endif /* CANARIS_VSSGUARD_RULES_H */
