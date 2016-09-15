##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'recog'

class MetasploitModule < Msf::Auxiliary


  # Exploit mixins should be called first
  include Msf::Exploit::Remote::DCERPC
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  # Aliases for common classes
  SIMPLE = Rex::Proto::SMB::SimpleClient
  XCEPT  = Rex::Proto::SMB::Exceptions
  CONST  = Rex::Proto::SMB::Constants


  def initialize
    super(
      'Name'        => 'SMB Version Detection',
      'Description' => 'Display version information about each system',
      'Author'      => 'hdm',
      'License'     => MSF_LICENSE
    )

    deregister_options('RPORT')
    deregister_options('SMBDIRECT')
    @smb_port = 445
  end

  def rport
    @smb_port || datastore['RPORT']
  end

  def smb_direct
    (@smb_port == 445)
  end

  # Fingerprint a single host
  #
  def run_host(ip)
    smb_ports = [445, 139]
    smb_ports.each do |pnum|
      @smb_port = pnum
      self.simple = nil

    begin
      res = smb_fingerprint()

      #
      # Create the note hash for smb.fingerprint
      #
      conf = {
         :native_os => res['native_os'],
         :native_lm => res['native_lm']
      }

      if res['os'] and res['os'] != 'Unknown'

        #
        # Create the note hash for fingerprint.match
        #
        match_conf = { }

        #
        # Create a descriptive string for service.info
        #
        desc = res['os'].dup

        if res['edition'].to_s.length > 0
          desc << " #{res['edition']}"
          conf[:os_edition] = res['edition']
          match_conf['os.edition'] = res['edition']
        end

        if res['sp'].to_s.length > 0
          desc << " #{res['sp'].downcase.gsub('service pack ', 'SP')}"
          conf[:os_sp] = res['sp']
          match_conf['os.version'] = res['sp']
        end

        if res['build'].to_s.length > 0
          desc << " (build:#{res['build']})"
          conf[:os_build] = res['build']
          match_conf['os.build'] = res['build']
        end

        if res['lang'].to_s.length > 0 and res['lang'] != 'Unknown'
          desc << " (language:#{res['lang']})"
          conf[:os_lang] = res['lang']
          match_conf['os.language'] = conf[:os_lang]
        end

        if simple.client.default_name
          desc << " (name:#{simple.client.default_name})"
          conf[:SMBName] = simple.client.default_name
          match_conf['host.name'] = conf[:SMBName]
        end

        if simple.client.default_domain
          desc << " (domain:#{simple.client.default_domain})"
          conf[:SMBDomain] = simple.client.default_domain
          match_conf['host.domain'] = conf[:SMBDomain]
        end

        print_status("Host is running #{desc}")

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
          :data  => match_conf
        )
      else
        desc = "#{res['native_os']} (#{res['native_lm']})"
        report_service(:host => ip, :port => rport, :name => 'smb', :info => desc)
        print_status("Host could not be identified: #{desc}")
      end

      # Report a smb.fingerprint hash of attributes for OS fingerprinting
      report_note(
        :host  => ip,
        :port  => rport,
        :proto => 'tcp',
        :ntype => 'smb.fingerprint',
        :data  => conf
      )

      disconnect

      break

    rescue ::Rex::Proto::SMB::Exceptions::NoReply => e
      next
    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode  => e
      next
    rescue ::Rex::Proto::SMB::Exceptions::LoginError => e
      # Vista has 139 open but doesnt like *SMBSERVER
      if(e.to_s =~ /server refused our NetBIOS/)
        next
      end

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
