##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'recog'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

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
  }

  def initialize
    super(
      'Name'        => 'SMB Version Detection',
      'Description' => 'Display version information about each system',
      'Author'      => ['hdm', 'Spencer McIntyre'],
      'License'     => MSF_LICENSE
    )

    deregister_options('RPORT')
    deregister_options('SMBDIRECT')
    deregister_options('SMB::ProtocolVersion')
    @smb_port = 445
  end

  def rport
    @smb_port || datastore['RPORT']
  end

  def smb_direct
    (@smb_port == 445)
  end

  def smb_versions
    preferred_dialect = nil
    supported = []
    (1..3).each do |version|
      begin
        simple = connect(false, versions: [version])
        protocol = simple.client.negotiate
      rescue Rex::Proto::SMB::Exceptions::Error, RubySMB::Error::RubySMBError
        next
      rescue Errno::ECONNRESET
        next
      rescue ::Exception => e
        vprint_error("#{rhost}: #{e.class} #{e}")
        next
      end

      preferred_dialect = simple.client.dialect
      if simple.client.is_a? RubySMB::Client
        preferred_dialect = SMB2_DIALECT_STRINGS[preferred_dialect]
      end

      supported << version unless protocol.nil?
    end

    # assume that if the server supports multiple versions, the preferred
    # dialect will correspond to the latest version
    {versions: supported, preferred_dialect: preferred_dialect}
  end

  def smb_description(res, nd_smb_fingerprint)
    #
    # Create the note hash for fingerprint.match
    #
    nd_fingerprint_match = { }

    #
    # Create a descriptive string for service.info
    #
    desc = res['os'].dup

    if res['edition'].to_s.length > 0
      desc << " #{res['edition']}"
      nd_smb_fingerprint[:os_edition] = res['edition']
      nd_fingerprint_match['os.edition'] = res['edition']
    end

    if res['sp'].to_s.length > 0
      desc << " #{res['sp'].downcase.gsub('service pack ', 'SP')}"
      nd_smb_fingerprint[:os_sp] = res['sp']
      nd_fingerprint_match['os.version'] = res['sp']
    end

    if res['build'].to_s.length > 0
      desc << " (build:#{res['build']})"
      nd_smb_fingerprint[:os_build] = res['build']
      nd_fingerprint_match['os.build'] = res['build']
    end

    if res['lang'].to_s.length > 0 and res['lang'] != 'Unknown'
      desc << " (language:#{res['lang']})"
      nd_smb_fingerprint[:os_lang] = res['lang']
      nd_fingerprint_match['os.language'] = nd_smb_fingerprint[:os_lang]
    end

    if simple.client.default_name
      desc << " (name:#{simple.client.default_name})"
      nd_smb_fingerprint[:SMBName] = simple.client.default_name
      nd_fingerprint_match['host.name'] = nd_smb_fingerprint[:SMBName]
    end

    {text: desc, fingerprint_match: nd_fingerprint_match, smb_fingerprint: nd_smb_fingerprint}
  end

  #
  # Fingerprint a single host
  #
  def run_host(ip)
    smb_ports = [445, 139]
    smb_ports.each do |pnum|
      @smb_port = pnum
      self.simple = nil

      begin
        res = smb_fingerprint()

        version_info = smb_versions
        #next unless versions.length
        desc = "SMB Detected (versions:#{version_info[:versions].join(', ')}) (preferred dialect:#{version_info[:preferred_dialect]})"

        if simple.client.peer_require_signing
          desc << " (signatures:required)"
        else
          desc << " (signatures:optional)"
          report_vuln({
            :host  => ip,
            :port  => rport,
            :proto => 'tcp',
            :name  => 'SMB Signing Is Not Required',
            :refs  => [
              SiteReference.new('URL', 'https://support.microsoft.com/en-us/help/161372/how-to-enable-smb-signing-in-windows-nt'),
              SiteReference.new('URL', 'https://support.microsoft.com/en-us/help/887429/overview-of-server-message-block-signing'),
            ]
          })
        end
        print_status(desc)

        #
        # Create the note hash for smb.fingerprint
        #
        nd_smb_fingerprint = {
           :native_os => res['native_os'],
           :native_lm => res['native_lm']
        }

        if res['os'] && res['os'] != 'Unknown'
          description = smb_description(res, nd_smb_fingerprint)
          desc = description[:text]
          nd_fingerprint_match = description[:fingerprint_match]
          nd_smb_fingerprint = description[:smb_fingerprint]

          if simple.client.default_domain
            if simple.client.default_domain.encoding.name == "UTF-8"
              desc << " (domain:#{simple.client.default_domain})"
            else
              # Workgroup names are in ANSI, but may contain invalid characters
              # Go through each char and convert/check
              temp_workgroup = simple.client.default_domain.dup
              desc << " (workgroup:"
              temp_workgroup.each_char do |i|
                begin
                  desc << i.encode("UTF-8")
                rescue Encoding::UndefinedConversionError => e
                  desc << '?'
                  vprint_error("Found incompatible (non-ANSI) character in Workgroup name. Replaced with '?'")
                end
              end
              desc << ")"
            end
            nd_smb_fingerprint[:SMBDomain] = simple.client.default_domain
            nd_fingerprint_match['host.domain'] = nd_smb_fingerprint[:SMBDomain]
          end

          print_good("  Host is running #{desc}")

          # Report the service with a friendly banner
          report_service(
            :host  => ip,
            :port  => rport,
            :proto => 'tcp',
            :name  => 'smb',
            :info  => desc
          )

          # Report a fingerprint.match hash for name, domain, and language
          # Ignore OS fields, as those are handled via smb.fingerprint
          report_note(
            :host  => ip,
            :port  => rport,
            :proto => 'tcp',
            :ntype => 'fingerprint.match',
            :data  => nd_fingerprint_match
          )
        else
          desc = ''
          if res['native_os'] || res['native_lm']
            desc = "#{res['native_os']} (#{res['native_lm']})"
            report_service(:host => ip, :port => rport, :name => 'smb', :info => desc)
            desc = ': ' + desc
          end
          print_status("  Host could not be identified#{desc}")
        end

        # Report a smb.fingerprint hash of attributes for OS fingerprinting
        report_note(
          :host  => ip,
          :port  => rport,
          :proto => 'tcp',
          :ntype => 'smb.fingerprint',
          :data  => nd_smb_fingerprint
        )

        disconnect

        break

      rescue ::Rex::Proto::SMB::Exceptions::NoReply => e
        next
      rescue ::Rex::Proto::SMB::Exceptions::ErrorCode  => e
        next
      rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
        # Vista has 139 open but doesnt like *SMBSERVER
        next if e.to_s =~ /server refused our NetBIOS/
        return
      rescue ::Timeout::Error
      rescue ::Rex::ConnectionError
        next

      rescue ::Exception => e
        print_error("#{rhost}: #{e.class} #{e}")
      ensure
        disconnect
      end
    end
  end
end
