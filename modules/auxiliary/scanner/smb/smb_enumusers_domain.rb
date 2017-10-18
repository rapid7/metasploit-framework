##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize
    super(
      'Name'        => 'SMB Domain User Enumeration',
      'Description' => 'Determine what domain users are logged into a remote system via a DCERPC to NetWkstaUserEnum.',
      'Author'      =>
        [
          'natron', # original module
          'Joshua D. Abraham <jabra[at]praetorian.com>', # database storage
        ],
      'References'  =>
        [
          [ 'URL', 'http://msdn.microsoft.com/en-us/library/aa370669%28VS.85%29.aspx' ]
        ],
      'License'     => MSF_LICENSE
    )

    deregister_options('RPORT', 'RHOST')

  end

  def parse_value(resp, idx)
    #val_length  = resp[idx,4].unpack("V")[0]
    idx += 4
    #val_offset = resp[idx,4].unpack("V")[0]
    idx += 4
    val_actual = resp[idx,4].unpack("V")[0]
    idx += 4
    value = resp[idx,val_actual*2]
    idx += val_actual * 2

    idx += val_actual % 2 * 2 # alignment

    return value,idx
  end

  def parse_net_wksta_enum_users_info(resp)
    accounts = [ Hash.new() ]

    idx = 20
    count = resp[idx,4].unpack("V")[0] # wkssvc_NetWkstaEnumUsersInfo -> Info -> PtrCt0 -> User() -> Ptr -> Max Count
    idx += 4

    1.upto(count) do
      # wkssvc_NetWkstaEnumUsersInfo -> Info -> PtrCt0 -> User() -> Ptr -> Ref ID
      idx += 4 # ref id name
      idx += 4 # ref id logon domain
      idx += 4 # ref id other domains
      idx += 4 # ref id logon server
    end

    1.upto(count) do
      # wkssvc_NetWkstaEnumUsersInfo -> Info -> PtrCt0 -> User() -> Ptr -> ID1 max count

      account_name,idx  = parse_value(resp, idx)
      logon_domain,idx  = parse_value(resp, idx)
      other_domains,idx = parse_value(resp, idx)
      logon_server,idx  = parse_value(resp, idx)

      accounts << {
        :account_name => account_name,
        :logon_domain => logon_domain,
        :other_domains => other_domains,
        :logon_server => logon_server
      }
    end

    accounts
  end

  def rport
    @rport || datastore['RPORT']
  end

  def smb_direct
    @smbdirect || datastore['SMBDirect']
  end

  def store_username(username, res, ip, rport)
    service_data = {
      address: ip,
      port: rport,
      service_name: 'smb',
      protocol: 'tcp',
      workspace_id: myworkspace_id,
      proof: res
    }

    credential_data = {
      origin_type: :service,
      module_fullname: fullname,
      username: username
    }

    credential_data.merge!(service_data)

    credential_core = create_credential(credential_data)

    login_data = {
      core: credential_core,
      status: Metasploit::Model::Login::Status::UNTRIED
    }

    login_data.merge!(service_data)
    create_credential_login(login_data)
  end

  def run_host(ip)

    [[139, false], [445, true]].each do |info|

    @rport = info[0]
    @smbdirect = info[1]

    begin
      connect()
      smb_login()

      uuid = [ '6bffd098-a112-3610-9833-46c3f87e345a', '1.0' ]

      handle = dcerpc_handle(
        uuid[0], uuid[1], 'ncacn_np', ["\\wkssvc"]
      )
      begin
        dcerpc_bind(handle)
        stub =
          NDR.uwstring("\\\\" + ip) + # Server Name
          NDR.long(1) +           # Level
          NDR.long(1) +           # Ctr
          NDR.long(rand(0xffffffff)) +  # ref id
          NDR.long(0) +           # entries read
          NDR.long(0) +           # null ptr to user0

          NDR.long(0xffffffff) +      # Prefmaxlen
          NDR.long(rand(0xffffffff)) +  # ref id
          NDR.long(0)             # null ptr to resume handle

        dcerpc.call(2,stub)

        resp = dcerpc.last_response ? dcerpc.last_response.stub_data : nil

        accounts = parse_net_wksta_enum_users_info(resp)
        accounts.shift

        if datastore['VERBOSE']
          accounts.each do |x|
            print_status x[:logon_domain] + "\\" + x[:account_name] +
              "\t(logon_server: #{x[:logon_server]}, other_domains: #{x[:other_domains]})"
          end
        else
          print_status "#{accounts.collect{|x| x[:logon_domain] + "\\" + x[:account_name]}.join(", ")}"
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
          store_username(comp_user, resp, ip, rport)
        end

      rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
        print_error("UUID #{uuid[0]} #{uuid[1]} ERROR 0x%.8x" % e.error_code)
        #puts e
        #return
      rescue ::Exception => e
        print_error("UUID #{uuid[0]} #{uuid[1]} ERROR #{$!}")
        #puts e
        #return
      end

      disconnect()
      return
    rescue ::Exception
      print_line($!.to_s)
    end
  end
end

end
