 Compile as a DLL and call the `GrantPrivilegeToUser` function with the username and privilege name.

C# example:

 [DllImport("UserPrivs.dll", CharSet = CharSet.Unicode)]
 public static extern bool GrantPrivilegeToUser(string userName, string privilegeName);
 
 GrantPrivilegeToUser("admin", "SeDebugPrivilege");
 GrantPrivilegeToUser("admin", "SeDebugPrivilege");
 GrantPrivilegeToUser("admin", "SeImpersonatePrivilege");
 GrantPrivilegeToUser("admin", "SeTcbPrivilege");
 GrantPrivilegeToUser("admin", "SeSecurityPrivilege");
 GrantPrivilegeToUser("admin", "SeBackupPrivilege");
 GrantPrivilegeToUser("admin", "SeRestorePrivilege");
