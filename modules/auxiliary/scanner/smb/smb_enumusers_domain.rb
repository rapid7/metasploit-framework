##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::MsWkst
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name' => 'SMB Domain User Enumeration',
      'Description' => 'Determine what domain users are logged into a remote system via a DCERPC to NetWkstaUserEnum.',
      'Author' => [
        'natron', # original module
        'Joshua D. Abraham <jabra[at]praetorian.com>', # database storage
        'NtAlexio2 <ntalexio2@gmail.com>', # refactor
      ],
      'References' => [
        [ 'URL', 'https://docs.microsoft.com/en-us/windows/win32/api/lmwksta/nf-lmwksta-netwkstauserenum' ]
      ],
      'License' => MSF_LICENSE,
    )
  end

  def rport
    @rport
  end

  def smb_direct
    @smb_direct
  end

  def connect(*args, **kwargs)
    super(*args, **kwargs, direct: @smb_direct)
  end

  def run_session
    smb_services = [{ port: self.simple.peerport, direct: self.simple.direct }]
    smb_services.map { |smb_service| run_service(smb_service[:port], smb_service[:direct]) }
  end

  def run_rhost
    if datastore['RPORT'].blank? || datastore['RPORT'] == 0
      smb_services = [
        { port: 445, direct: true },
        { port: 139, direct: false }
      ]
    else
      smb_services = [
        { port: datastore['RPORT'], direct: datastore['SMBDirect'] }
      ]
    end

    smb_services.map { |smb_service| run_service(smb_service[:port], smb_service[:direct]) }
  end

  def run_service(port, direct)
    @rport = port
    @smb_direct = direct

    ipc_tree = connect_ipc
    wkssvc_pipe = connect_wkssvc(ipc_tree)
    endpoint = RubySMB::Dcerpc::Wkssvc.freeze

    user_info = user_enum(endpoint::WKSTA_USER_INFO_1)
    user_info.wkui1_buffer
  rescue Msf::Exploit::Remote::SMB::Client::Ipc::SmbIpcAuthenticationError => e
    print_warning(e.message)
    nil
  rescue RubySMB::Error::RubySMBError => e
    print_error("Error: #{e.message}")
    nil
  rescue ::Timeout::Error
  rescue ::Exception => e
    print_error("Error: #{e.class} #{e}")
    nil
  ensure
    disconnect_wkssvc
  end

  def run_host(_ip)
    if session
      self.simple = session.simple_client
      results = run_session
    else
      results = run_rhost
    end

    unless results.to_s.empty?
      accounts = [ Hash.new() ]
      results.compact.each do |result_set|
        result_set.each { |result|
          accounts << {
            :account_name => result.wkui1_username.encode('UTF-8'),
            :logon_domain => result.wkui1_logon_domain.encode('UTF-8'),
            :other_domains => result.wkui1_oth_domains.encode('UTF-8'),
            :logon_server => result.wkui1_logon_server.encode('UTF-8')
          }
        }
      end
      accounts.shift

      if datastore['VERBOSE']
        accounts.each do |x|
          print_status x[:logon_domain] + "\\" + x[:account_name] +
                       "\t(logon_server: #{x[:logon_server]}, other_domains: #{x[:other_domains]})"
        end
      else
        print_status "#{accounts.collect { |x| x[:logon_domain] + "\\" + x[:account_name] }.join(", ")}"
      end

      found_accounts = []
      accounts.each do |x|
        comp_user = x[:logon_domain] + "\\" + x[:account_name]
        found_accounts.push(comp_user.scan(/[[:print:]]/).join) unless found_accounts.include?(comp_user.scan(/[[:print:]]/).join)
      end

      found_accounts.each do |comp_user|
        if comp_user.to_s =~ /\$$/
          next
        end

        print_good("Found user: #{comp_user}")
      end

    end
  end
end
