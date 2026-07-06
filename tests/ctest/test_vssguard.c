// SPDX-License-Identifier: GPL-2.0
/* Test unitaire C de la logique de matching VssGuard (Phase 6).
 * Compile la même en-tête portable que le driver Windows (vssguard_rules.h)
 * avec gcc (wchar_t 4 octets) et vérifie la classification des command-lines.
 */
#include "vssguard_rules.h"
#include <stdio.h>

static int failures = 0;
#define CHECK(cond, msg) do { \
	if (!(cond)) { printf("  X %s\n", msg); failures++; } \
	else         { printf("  OK %s\n", msg); } \
} while (0)

int main(void)
{
	printf("== test_vssguard ==\n");

	/* --- vrais positifs (doivent matcher) --- */
	CHECK(vssguard_classify(L"C:\\Windows\\System32\\vssadmin.exe",
		L"vssadmin delete shadows /all /quiet") == VG_VSSADMIN_DELETE,
		"vssadmin delete shadows");
	CHECK(vssguard_classify(L"vssadmin.exe",
		L"vssadmin  Delete  Shadows /All") == VG_VSSADMIN_DELETE,
		"insensible à la casse + espaces");
	CHECK(vssguard_classify(L"C:\\Windows\\System32\\vssadmin.exe",
		L"vssadmin resize shadowstorage /for=c: /maxsize=1MB") == VG_VSSADMIN_RESIZE,
		"vssadmin resize shadowstorage");
	CHECK(vssguard_classify(L"wmic.exe",
		L"wmic shadowcopy delete") == VG_WMIC_SHADOW_DELETE,
		"wmic shadowcopy delete");
	CHECK(vssguard_classify(L"bcdedit.exe",
		L"bcdedit /set {default} recoveryenabled No") == VG_BCDEDIT_RECOVERY,
		"bcdedit recoveryenabled no");
	CHECK(vssguard_classify(L"bcdedit.exe",
		L"bcdedit /set {default} bootstatuspolicy ignoreallfailures") == VG_BCDEDIT_RECOVERY,
		"bcdedit bootstatuspolicy ignoreallfailures");
	CHECK(vssguard_classify(L"wbadmin.exe",
		L"wbadmin delete catalog -quiet") == VG_WBADMIN_DELETE,
		"wbadmin delete catalog");
	CHECK(vssguard_classify(L"powershell.exe",
		L"powershell -c \"Get-WmiObject Win32_Shadowcopy | Remove-WmiObject\"")
		== VG_PS_SHADOW_DELETE, "powershell win32_shadowcopy remove");

	/* --- vrais négatifs (ne doivent PAS matcher) --- */
	CHECK(vssguard_classify(L"vssadmin.exe", L"vssadmin list shadows") == VG_NONE,
		"vssadmin list shadows (bénin)");
	CHECK(vssguard_classify(L"notepad.exe", L"notepad C:\\doc.txt") == VG_NONE,
		"notepad (bénin)");
	CHECK(vssguard_classify(L"bcdedit.exe", L"bcdedit /enum") == VG_NONE,
		"bcdedit /enum (bénin)");
	CHECK(vssguard_classify(L"wbadmin.exe",
		L"wbadmin get status") == VG_NONE, "wbadmin get status (bénin)");
	CHECK(vssguard_classify(L"powershell.exe", L"powershell Get-Process") == VG_NONE,
		"powershell Get-Process (bénin)");

	/* référence vssguard_reason() (partagée avec le driver) */
	printf("  exemple de libellé: \"%s\"\n",
	       vssguard_reason(vssguard_classify(L"vssadmin.exe",
					 L"vssadmin delete shadows /all")));

	printf(failures ? "\nECHECS: %d\n" : "\nOK (test_vssguard)\n", failures);
	return failures ? 1 : 0;
}
