/* 
    Author      : Gregory King
    Date        : 07/17/25
	Description : This code grants a specified privilege to a user account on a Windows system.

	Usage       : Compile as a DLL and call the `GrantPrivilegeToUser` function with the username and privilege name.
                : [DllImport("UserPrivs.dll", CharSet = CharSet.Unicode)]
                : public static extern bool GrantPrivilegeToUser(string userName, string privilegeName);
				: GrantPrivilegeToUser("admin", "SeDebugPrivilege");
                : GrantPrivilegeToUser("admin", "SeDebugPrivilege");
                : GrantPrivilegeToUser("admin", "SeImpersonatePrivilege");
                : GrantPrivilegeToUser("admin", "SeTcbPrivilege");
                : GrantPrivilegeToUser("admin", "SeSecurityPrivilege");
                : GrantPrivilegeToUser("admin", "SeBackupPrivilege");
                : GrantPrivilegeToUser("admin", "SeRestorePrivilege");
*/

#include <windows.h>
#include <ntsecapi.h>
#include <sddl.h>

#pragma comment(lib, "advapi32.lib")

/* supported privilege names */
const wchar_t* privs[] = {
    SE_DEBUG_NAME,
    SE_IMPERSONATE_NAME,
    SE_TCB_NAME,
    SE_SECURITY_NAME,
    SE_BACKUP_NAME,
    SE_RESTORE_NAME
};

/* grants the specified privilege to the given user account. returns true on success, false on failure */
extern "C" __declspec(dllexport) BOOL GrantPrivilegeToUser(
    const wchar_t* userName,
    const wchar_t* privilegeName)
{
    LSA_HANDLE policyHandle = nullptr;
    LSA_OBJECT_ATTRIBUTES objectAttributes = {0};
    PSID pSid = nullptr;
    DWORD sidSize = 0, domainSize = 0;
    SID_NAME_USE sidType;
    BOOL result = FALSE;

    /* get the sid for the user */
    LookupAccountNameW(nullptr, userName, nullptr, &sidSize, nullptr, &domainSize, &sidType);
    pSid = (PSID)malloc(sidSize);
    wchar_t* domainName = (wchar_t*)malloc(domainSize * sizeof(wchar_t));
    if (!LookupAccountNameW(nullptr, userName, pSid, &sidSize, domainName, &domainSize, &sidType)) {
        goto cleanup;
    }

    /* open the local security policy */
    if (LsaOpenPolicy(nullptr, &objectAttributes, POLICY_ALL_ACCESS, &policyHandle) != 0) {
        goto cleanup;
    }

    /* prepare privilege string */
    LSA_UNICODE_STRING privilegeString;
    privilegeString.Buffer = (PWSTR)privilegeName;
    privilegeString.Length = (USHORT)wcslen(privilegeName) * sizeof(wchar_t);
    privilegeString.MaximumLength = privilegeString.Length + sizeof(wchar_t);

    /* grant the privilege */
    if (LsaAddAccountRights(policyHandle, pSid, &privilegeString, 1) == 0) {
        result = TRUE;
    }

cleanup:
    if (policyHandle) LsaClose(policyHandle);
    if (pSid) free(pSid);
    if (domainName) free(domainName);
    return result;
}