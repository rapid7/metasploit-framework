##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::MsLsad
  include Msf::Exploit::Remote::MsLsat
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  include Msf::OptionalSession::SMB

  def initialize
    super(
      'Name' => 'SMB SID User Enumeration (LookupSid)',
      'Description' => 'Determine what users exist via brute force SID lookups.
        This module can enumerate both local and domain accounts by setting
        ACTION to either LOCAL or DOMAIN',
      'Author' => 'hdm',
      'License' => MSF_LICENSE,
      'DefaultOptions' => {
        # Samba doesn't like this option, so we disable so we are compatible with
        # both Windows and Samba for enumeration.
        'DCERPC::fake_bind_multi' => false
      },
      'Actions' => [
        ['LOCAL', { 'Description' => 'Enumerate local accounts' } ],
        ['DOMAIN', { 'Description' => 'Enumerate domain accounts' } ]
      ],
      'DefaultAction' => 'LOCAL',
    )

    register_options(
      [
        OptInt.new('MinRID', [ false, "Starting RID to check", 500 ]),
        OptInt.new('MaxRID', [ false, "Maximum RID to check", 4000 ])
      ]
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
    lsarpc_pipe = connect_lsarpc(ipc_tree)
    endpoint = RubySMB::Dcerpc::Lsarpc.freeze
    policy_handle = open_policy2(endpoint::SECURITY_IMPERSONATION, endpoint::SECURITY_CONTEXT_CONTINUOUS_UPDATES, endpoint::MAXIMUM_ALLOWED)

    account_policy = query_information_policy(policy_handle, endpoint::POLICY_ACCOUNT_DOMAIN_INFORMATION)
    primary_policy = query_information_policy(policy_handle, endpoint::POLICY_PRIMARY_DOMAIN_INFORMATION)

    info = {
      local: {
        name: primary_policy[:policy_information][:name].encode('ASCII-8BIT'),
        sid: primary_policy[:policy_information][:sid].to_s.encode('ASCII-8BIT')
      },
      domain: {
        name: account_policy[:policy_information][:domain_name].encode('ASCII-8BIT'),
        sid: account_policy[:policy_information][:domain_sid].to_s.encode('ASCII-8BIT')
      }
    }

    # Store the domain information
    report_note(
      :host => self.simple.peerhost,
      :proto => 'tcp',
      :port => self.simple.peerport,
      :type => 'smb.domain.lookupsid',
      :data => { :domain => info[:domain] }
    )

    pipe_info = "PIPE(#{lsarpc_pipe.name})"
    local_info = "LOCAL(#{info[:local][:name]} - #{info[:local][:sid]})"
    domain_info = "DOMAIN(#{info[:domain][:name]} - #{info[:domain][:sid]})"
    all_info = "#{pipe_info} #{local_info} #{domain_info}"
    print_status(all_info)

    target_sid = case action.name.upcase
                 when 'LOCAL'
                   info[:local][:sid] == 'null' ? info[:domain][:sid] : info[:local][:sid]
                 when 'DOMAIN'
                   # Fallthrough to the host SID if no domain SID was returned
                   if info[:domain][:sid] == 'null'
                     print_error 'No domain SID identified, falling back to the local SID...'
                     info[:local][:sid]
                   else
                     info[:domain][:sid]
                   end
                 end

    min_rid = datastore['MinRID']
    max_rid = datastore['MaxRID']

    output = []

    # Brute force through a common RID range
    min_rid.upto(max_rid) do |rid|
      print "%bld%blu[*]%clr Trying RID #{rid} / #{max_rid}\r"
      begin
        sid = "#{target_sid}-#{rid}"
        sids = lookup_sids(policy_handle, sid, endpoint::LSAP_LOOKUP_WKSTA)
        sids.each do |sid|
          output << [ map_security_principal_to_string(sid[:type]), sid[:name], rid ]
        end
      rescue RubySMB::Dcerpc::Error::LsarpcError => e
        # Ignore unmapped RIDs
        unless e.message.match?(/STATUS_NONE_MAPPED/) || e.message.match?(/STATUS_SOME_MAPPED/)
          wlog e
        end
      end
    end

    output
  rescue Msf::Exploit::Remote::SMB::Client::Ipc::SmbIpcAuthenticationError => e
    print_warning e.message
    nil
  rescue ::Timeout::Error
  rescue ::Exception => e
    print_error("Error: #{e.class} #{e}")
  ensure
    close_policy(policy_handle)
    disconnect_lsarpc
    disconnect_ipc(ipc_tree)
  end

  def format_results(results)
    sids_table = Rex::Text::Table.new(
      'Indent' => 4,
      'Header' => "SMB Lookup SIDs Output",
      'Columns' =>
        [
          'Type',
          'Name',
          'RID'
        ],
      'SortIndex' => 2 # Sort by RID
    )

    # Each result contains 0 or more arrays containing: SID Type, Name, RID
    results.compact.each do |result_set|
      result_set.each { |result| sids_table << result }
    end

    sids_table
  end

  # Fingerprint a single host
  def run_host(_ip)
    if session
      self.simple = session.simple_client
      results = run_session
    else
      results = run_rhost
    end

    results_table = format_results(results)
    results_table.rows = results_table.rows.uniq # Remove potentially duplicate entries from port 139 & 445

    print_line
    print_line results_table.to_s
  end
end
