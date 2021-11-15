##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(
      update_info(
        info,
        'Name' => 'SMB Share Enumeration',
        'Description' => %q{
          This module determines what shares are provided by the SMB service and which ones
          are readable/writable. It also collects additional information such as share types,
          directories, files, time stamps, etc.
        },
        'Author' => [
          'hdm',
          'nebulus',
          'sinn3r',
          'r3dy',
          'altonjx',
          'sjanusz-r7'
        ],
        'License' => MSF_LICENSE,
        'DefaultOptions' => {
          'DCERPC::fake_bind_multi' => false
        }
      )
    )

    register_options(
      [
        OptBool.new('SpiderShares', [false, 'Spider shares recursively', false]),
        OptBool.new('ShowFiles', [true, 'Show detailed information when spidering', false]),
        OptBool.new('SpiderProfiles', [false, 'Spider only user profiles when share = C$', true]),
        OptEnum.new('LogSpider', [false, '0 = disabled, 1 = CSV, 2 = table (txt), 3 = one liner (txt)', 3, [0, 1, 2, 3]]),
        OptInt.new('MaxDepth', [true, 'Max number of subdirectories to spider', 999]),
      ]
    )

    deregister_options('RPORT')
  end

  # Updated types for RubySMB. These are all the types we can ever receive from calling net_share_enum_all
  ENUMERABLE_SHARE_TYPES = ['DISK', 'TEMPORARY'].freeze
  SKIPPABLE_SHARE_TYPES = ['PRINTER', 'IPC', 'DEVICE', 'SPECIAL'].freeze

  def rport
    @rport || datastore['RPORT']
  end

  def smb_direct
    @smb_redirect || datastore['SMBDirect']
  end

  def srvsvc
    @srvsvc || datastore['USE_SRVSVC_ONLY']
  end

  def enum_tree(tree, share, subdir = '')
    subdir = subdir[1..subdir.length] if subdir.starts_with?('\\')
    read = tree.permissions.read_ea == 1
    write = tree.permissions.write_ea == 1
    skip = false

    if ENUMERABLE_SHARE_TYPES.include? share[:type]
      msg = share[:type]
    elsif SKIPPABLE_SHARE_TYPES.include? share[:type]
      msg = share[:type]
      skip = true
    else
      msg = "Unhandled Device Type (#{share[:type]})"
      skip = true
    end

    print_status "Skipping share #{share[:name].strip} as it is of type #{share[:type]}" if skip
    return read, write, msg, nil if skip

    # Create list after possibly skipping a share we wouldn't be able to access.
    begin
      list = tree.list(directory: subdir)
    rescue RubySMB::Error::UnexpectedStatusCode => e
      print_error e.to_s
      return read, write, msg, nil
    end

    rfd = []
    list.entries.each do |file|
      file_name = file.file_name.strip.encode('UTF-8')
      next if file_name == '.' || file_name == '..'

      rfd.push(file)
    end

    return read, write, msg, rfd
  rescue RubySMB::Error::UnexpectedStatusCode => e
    print_error e.to_s
    return false, false, nil, nil
  end

  def get_os_info(ip)
    os = smb_fingerprint
    if os['os'] != 'Unknown'
      os_info = "#{os['os']} #{os['sp']} (#{os['lang']})"
    end
    if os_info
      report_service(
        host: ip,
        port: rport,
        proto: 'tcp',
        name: 'smb',
        info: os_info
      )
    end

    os_info
  end

  def get_user_dirs(tree, share, base, sub_dirs)
    dirs = []
    usernames = []

    _read, _write, _type, files = enum_tree(tree, share, base)

    return dirs if files.nil?

    files.each do |f|
      usernames.push(f)
    end

    usernames.each do |username|
      sub_dirs.each do |sub_dir|
        dirs.push("#{base}\\#{username}\\#{sub_dir}")
      end
    end

    dirs
  end

  def profile_options(tree, share)
    old_dirs = ['My Documents', 'Desktop']
    new_dirs = ['Desktop', 'Documents', 'Downloads', 'Music', 'Pictures', 'Videos']

    dirs = get_user_dirs(tree, share, 'Documents and Settings', old_dirs)
    if dirs.blank?
      dirs = get_user_dirs(tree, share, 'Users', new_dirs)
    end

    dirs
  end

  def get_files_info(ip, shares)
    # Creating a separate file for each IP address's results.
    detailed_tbl = Rex::Text::Table.new(
      'Header' => "Spidered results for #{ip}.",
      'Indent' => 1,
      'Columns' => [ 'IP Address', 'Type', 'Share', 'Path', 'Name', 'Created', 'Accessed', 'Written', 'Changed', 'Size' ]
    )

    logdata = ''

    shares.each do |share|
      share_name = share[:name].strip
      if (share_name == 'ADMIN$') || (share_name == 'IPC$')
        next
      end

      if (share_name == 'Users') && !datastore['SpiderProfiles']
        next
      end

      if !datastore['ShowFiles']
        print_status("Spidering #{share_name}.")
      end

      begin
        tree = simple.client.tree_connect("\\\\#{ip}\\#{share_name}")
      rescue RubySMB::Error::UnexpectedStatusCode => e
        print_error "Error when trying to connect to share #{share_name} - #{e.status_code.name}"
        print_status "Spidering #{share_name} complete."
        next
      end

      subdirs = ['']
      if (share_name == 'C$') && datastore['SpiderProfiles']
        subdirs = profile_options(tree, share)
      end
      until subdirs.empty?
        depth = subdirs.first.count('\\')

        if share_name == 'C$'
          if datastore['SpiderProfiles']
            if (depth - 2) > datastore['MaxDepth']
              subdirs.shift
              next
            end
          else
            subdirs.shift
            next
          end
        end

        if depth > datastore['MaxDepth']
          subdirs.shift
          next
        end

        read, write, _type, files = enum_tree(tree, share, subdirs.first)

        if files && (read || write)
          if files.empty?
            subdirs.shift
            next
          end

          header = ''
          pretty_tbl = Rex::Text::Table.new(
            'Header' => header,
            'Indent' => 1,
            'Columns' => [ 'Type', 'Name', 'Created', 'Accessed', 'Written', 'Changed', 'Size' ]
          )

          if simple.client.default_domain && simple.client.default_name
            header << " \\\\#{simple.client.default_domain}"
          end
          header << "\\#{share_name.sub('C$', 'C$\\')}" if simple.client.default_name
          header << subdirs.first

          files.each do |file|
            fname = file.file_name.encode('UTF-8')
            tcr = file.create_time.to_datetime
            tac = file.last_access.to_datetime
            twr = file.last_write.to_datetime
            tch = file.last_change.to_datetime

            # Add subdirectories to list to use if SpiderShare is enabled.
            if file.file_attributes.directory == 1
              fa = 'DIR'
              subdirs.push(subdirs.first + '\\' + fname)
            else
              fa = 'FILE'
              sz = file.end_of_file
            end

            # Filename is too long for the UI table, cut it.
            fname = "#{fname[0, 35]}..." if fname.length > 35

            pretty_tbl << [fa || 'Unknown', fname, tcr, tac, twr, tch, sz]
            detailed_tbl << [ip.to_s, fa || 'Unknown', share_name, subdirs.first + '\\', fname, tcr, tac, twr, tch, sz]
            logdata << "#{ip}\\#{share_name.sub('C$', 'C$\\')}#{subdirs.first}\\#{fname.encode}\n"
          end
          print_good(pretty_tbl.to_s) if datastore['ShowFiles']
        end
        subdirs.shift
      end

      tree.disconnect! # simple.client.tree_disconnect is the same. Which is preferred?
      print_status("Spidering #{share_name} complete.") unless datastore['ShowFiles']
    end
    unless detailed_tbl.rows.empty?
      if datastore['LogSpider'] == '1'
        p = store_loot('smb.enumshares', 'text/csv', ip, detailed_tbl.to_csv)
        print_good("info saved in: #{p}")
      elsif datastore['LogSpider'] == '2'
        p = store_loot('smb.enumshares', 'text/plain', ip, detailed_tbl)
        print_good("info saved in: #{p}")
      elsif datastore['LogSpider'] == '3'
        p = store_loot('smb.enumshares', 'text/plain', ip, logdata)
        print_good("info saved in: #{p}")
      end
    end
  end

  def run_host(ip)
    shares = []

    [{ port: 139, redirect: false }, { port: 445, redirect: true} ].each do |info|
      @rport = info[:port]
      @smb_redirect = info[:redirect]

      begin
        print_status 'Starting module'
        if rport == 139
          connect(versions: [1])
        else
          connect(versions: [1, 2, 3])
        end
        smb_login
        shares = simple.client.net_share_enum_all(ip)
        os_info = get_os_info(ip)
        print_status(os_info) if os_info

        if shares.empty?
          print_status('No shares available')
        else
          shares.each do |share|
            print_good("#{share[:name]} - (#{share[:type]}) #{share[:comment]}")
          end

          # Map RubySMB shares to the same data format as it was with Rex SMB
          report_shares = shares.map { |share| [share[:name], share[:type], share[:comment]] }
          report_note(
            host: ip,
            proto: 'tcp',
            port: rport,
            type: 'smb.shares',
            data: { shares: report_shares },
            update: :unique_data
          )

          if datastore['SpiderShares']
            get_files_info(ip, shares)
          end
        end
      rescue ::Interrupt
        raise $ERROR_INFO
      rescue Errno::ECONNRESET => e
        vprint_error(e.message)
      rescue Errno::ENOPROTOOPT
        print_status('Wait 5 seconds before retrying...')
        select(nil, nil, nil, 5)
        retry
      rescue Rex::ConnectionTimeout => e
        print_error e.to_s
        return
      rescue Rex::Proto::SMB::Exceptions::LoginError => e
        print_error e.to_s
      rescue StandardError => e
        vprint_error("Error: '#{ip}' '#{e.class}' '#{e}'")
      ensure
        disconnect
      end

      # if we already got results, not need to try on another port
      return unless shares.empty?
    end
  end
end
