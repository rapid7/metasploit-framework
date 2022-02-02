##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'recog'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  SMB2_DIALECT_STRINGS = {
    '0x0202' => 'SMB 2.0.2',
    '0x0210' => 'SMB 2.1',
    '0x0300' => 'SMB 3.0',
    '0x0302' => 'SMB 3.0.2',
    '0x0311' => 'SMB 3.1.1',
    '0x02ff' => 'SMB 2.???'
  }.freeze

  def initialize
    super(
      'Name' => 'SMB Version Detection',
      'Description' => %q{
        Fingerprint and display version information about SMB servers. Protocol
        information and host operating system (if available) will be reported.
        Host operating system detection requires the remote server to support
        version 1 of the SMB protocol. Compression and encryption capability
        negotiation is only present in version 3.1.1.
      },
      'Author' => ['hdm', 'Spencer McIntyre', 'Christophe De La Fuente'],
      'License' => MSF_LICENSE
    )

    deregister_options('RPORT', 'SMBDIRECT', 'SMB::ProtocolVersion')
  end

  def rport
    @smb_port
  end

  def smb_direct
    (@smb_port == 445)
  end

  def seconds_to_timespan(seconds)
    timespan = []
    [
      ['w', 60 * 60 * 24 * 7], # weeks
      ['d', 60 * 60 * 24], # days
      ['h', 60 * 60], # hours
      ['m', 60], # minutes
      ['s', 1] # seconds
    ].each do |spec, span|
      if seconds > span || !timespan.empty?
        timespan << "#{(seconds / span).floor}#{spec}"
        seconds %= span
      end
    end

    timespan.join(' ')
  end

  def smb_proto_info
    info = {
      capabilities: {},
      versions: []
    }
    versions = [1, 2, 3]
    while !versions.empty?
      begin
        simple = connect(false, versions: versions)
        protocol = simple.client.negotiate
      rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError
        break
      rescue Errno::ECONNRESET
        break
      rescue ::Exception => e # rubocop:disable Lint/RescueException
        vprint_error("#{rhost}: #{e.class} #{e}")
        break
      end

      break if protocol.nil?
      version = { 'SMB2' => 2, 'SMB3' => 3 }.fetch(protocol, 1)
      versions.select! { |v| v < version }

      dialect = simple.client.dialect
      if simple.client.is_a? RubySMB::Client
        if dialect == '0x0311'
          info[:capabilities][:compression] = simple.client.server_compression_algorithms.map do |algorithm|
            RubySMB::SMB2::CompressionCapabilities::COMPRESSION_ALGORITHM_MAP[algorithm]
          end
          info[:capabilities][:encryption] = simple.client.server_encryption_algorithms.map do |algorithm|
            RubySMB::SMB2::EncryptionCapabilities::ENCRYPTION_ALGORITHM_MAP[algorithm]
          end
        end
        # assume that if the server supports multiple versions, the preferred
        # dialect will correspond to the latest version
        dialect = SMB2_DIALECT_STRINGS[dialect]

        if simple.client.server_start_time && simple.client.server_system_time
          uptime = simple.client.server_system_time - simple.client.server_start_time
          info[:uptime] = seconds_to_timespan(uptime)
        end
        info[:server_guid] = simple.client.server_guid

        unless info.key? :auth_domain
          begin
            simple.client.authenticate
          rescue RubySMB::Error::RubySMBError
            info[:auth_domain] = nil
          else
            info[:auth_domain] = simple.client.default_domain
          end
        end
      end

      info[:preferred_dialect] = dialect unless info.key? :preferred_dialect
      info[:versions] << version
    end

    info[:versions].reverse!
    info
  end

  def smb_os_description(res, nd_smb_fingerprint)
    #
    # Create the note hash for fingerprint.match
    #
    nd_fingerprint_match = {}

    #
    # Create a descriptive string for service.info
    #
    desc = res['os'].dup

    if !res['edition'].to_s.empty?
      desc << " #{res['edition']}"
      nd_smb_fingerprint[:os_edition] = res['edition']
      nd_fingerprint_match['os.edition'] = res['edition']
    end

    if !res['sp'].to_s.empty?
      desc << " #{res['sp'].downcase.gsub('service pack ', 'SP')}"
      nd_smb_fingerprint[:os_sp] = res['sp']
      nd_fingerprint_match['os.version'] = res['sp']
    end

    if !res['build'].to_s.empty?
      desc << " (build:#{res['build']})"
      nd_smb_fingerprint[:os_build] = res['build']
      nd_fingerprint_match['os.build'] = res['build']
    end

    if !res['lang'].to_s.empty? && res['lang'] != 'Unknown'
      desc << " (language:#{res['lang']})"
      nd_smb_fingerprint[:os_lang] = res['lang']
      nd_fingerprint_match['os.language'] = nd_smb_fingerprint[:os_lang]
    end

    if simple.client.default_name
      desc << " (name:#{simple.client.default_name})"
      nd_smb_fingerprint[:SMBName] = simple.client.default_name
      nd_fingerprint_match['host.name'] = nd_smb_fingerprint[:SMBName]
    end

    { text: desc, fingerprint_match: nd_fingerprint_match, smb_fingerprint: nd_smb_fingerprint }
  end

  #
  # Fingerprint a single host
  #
  def run_host(ip)
    smb_ports = [445, 139]
    lines = [] # defer status output to the very end to group lines together by host
    smb_ports.each do |pnum|
      @smb_port = pnum
      self.simple = nil

      begin
        res = smb_fingerprint

        info = smb_proto_info
        desc = "SMB Detected (versions:#{info[:versions].join(', ')}) (preferred dialect:#{info[:preferred_dialect]})"
        info[:capabilities].each do |name, values|
          desc << " (#{name} capabilities:#{values.join(', ')})"
        end

        if simple.client.peer_require_signing
          desc << ' (signatures:required)'
        else
          desc << ' (signatures:optional)'
          report_vuln({
            host: ip,
            port: rport,
            proto: 'tcp',
            name: 'SMB Signing Is Not Required',
            refs: [
              SiteReference.new('URL', 'https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt'),
              SiteReference.new('URL', 'https://support.microsoft.com/en-us/help/887429/overview-of-server-message-block-signing'),
            ]
          })
        end
        desc << " (uptime:#{info[:uptime]})" if info[:uptime]
        desc << " (guid:#{Rex::Text.to_guid(info[:server_guid])})" if info[:server_guid]
        desc << " (authentication domain:#{info[:auth_domain]})" if info[:auth_domain]
        lines << { type: :status, message: desc }

        #
        # Create the note hash for smb.fingerprint
        #
        nd_smb_fingerprint = {
          native_os: res['native_os'],
          native_lm: res['native_lm']
        }

        if res['os'] && res['os'] != 'Unknown'
          description = smb_os_description(res, nd_smb_fingerprint)
          desc = description[:text]
          nd_fingerprint_match = description[:fingerprint_match]
          nd_smb_fingerprint = description[:smb_fingerprint]

          if simple.client.default_domain
            if simple.client.default_domain.encoding.name == 'UTF-8'
              desc << " (domain:#{simple.client.default_domain})"
            else
              # Workgroup names are in ANSI, but may contain invalid characters
              # Go through each char and convert/check
              temp_workgroup = simple.client.default_domain.dup
              desc << ' (workgroup:'
              temp_workgroup.each_char do |i|
                begin
                  desc << i.encode('UTF-8')
                rescue ::Encoding::UndefinedConversionError # rubocop:disable Metrics/BlockNesting
                  desc << '?'
                end
              end
              desc << ')'
            end
            nd_smb_fingerprint[:SMBDomain] = simple.client.default_domain
            nd_fingerprint_match['host.domain'] = nd_smb_fingerprint[:SMBDomain]
          end

          lines << { type: :good, message: "  Host is running #{desc}" }

          # Report the service with a friendly banner
          report_service(
            host: ip,
            port: rport,
            proto: 'tcp',
            name: 'smb',
            info: desc
          )

          # Report a fingerprint.match hash for name, domain, and language
          # Ignore OS fields, as those are handled via smb.fingerprint
          report_note(
            host: ip,
            port: rport,
            proto: 'tcp',
            ntype: 'fingerprint.match',
            data: nd_fingerprint_match
          )
        elsif res['native_os'] || res['native_lm']
          desc = "#{res['native_os']} (#{res['native_lm']})"
          report_service(host: ip, port: rport, name: 'smb', info: desc)
          lines << { type: :status, message: "  Host could not be identified: #{desc}" }
        else
          lines << { type: :status, message: '  Host could not be identified', verbose: true }
        end

        # Report a smb.fingerprint hash of attributes for OS fingerprinting
        report_note(
          host: ip,
          port: rport,
          proto: 'tcp',
          ntype: 'smb.fingerprint',
          data: nd_smb_fingerprint
        )

        disconnect

        break
      rescue ::Rex::Proto::SMB::Exceptions::NoReply
        next
      rescue ::Rex::Proto::SMB::Exceptions::ErrorCode
        next
      rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
        # Vista has 139 open but doesnt like *SMBSERVER
        next if e.to_s =~ /server refused our NetBIOS/

        break
      rescue ::Timeout::Error
        next
      rescue ::Rex::ConnectionError
        next
      rescue ::Exception => e # rubocop:disable Lint/RescueException
        print_error("#{rhost}: #{e.class} #{e}")
      ensure
        disconnect

        lines.each do |line|
          send "#{ line[:verbose] ? 'v' : '' }print_#{line[:type]}", line[:message]
        end
        lines = []
      end
    end
  end
end
