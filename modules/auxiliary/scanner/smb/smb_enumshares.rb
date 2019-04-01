##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Auxiliary

  # Exploit mixins should be called first
  include Msf::Exploit::Remote::SMB::Client
  include Msf::Exploit::Remote::SMB::Client::Authenticated
  include Msf::Exploit::Remote::DCERPC

  # Scanner mixin should be near last
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'           => 'SMB Share Enumeration',
      'Description'    => %q{
        This module determines what shares are provided by the SMB service and which ones
        are readable/writable. It also collects additional information such as share types,
        directories, files, time stamps, etc.

        By default, a netshareenum request is done in order to retrieve share information,
        but if this fails, you may also fall back to SRVSVC.
      },
      'Author'         =>
        [
          'hdm',
          'nebulus',
          'sinn3r',
          'r3dy',
          'altonjx'
        ],
      'License'        => MSF_LICENSE,
      'DefaultOptions' =>
        {
          'DCERPC::fake_bind_multi' => false
        }
    ))

    register_options(
      [
        OptBool.new('SpiderShares',      [false, 'Spider shares recursively', false]),
        OptBool.new('ShowFiles',        [true, 'Show detailed information when spidering', false]),
        OptBool.new('SpiderProfiles',  [false, 'Spider only user profiles when share = C$', true]),
        OptEnum.new('LogSpider',      [false, '0 = disabled, 1 = CSV, 2 = table (txt), 3 = one liner (txt)', 3, [0,1,2,3]]),
        OptInt.new('MaxDepth',      [true, 'Max number of subdirectories to spider', 999]),
      ])

    deregister_options('RPORT')
  end

  def device_type_int_to_text(device_type)
    types = [
      "UNSET", "BEEP", "CDROM", "CDROM FILE SYSTEM", "CONTROLLER", "DATALINK",
      "DFS", "DISK", "DISK FILE SYSTEM", "FILE SYSTEM", "INPORT PORT", "KEYBOARD",
      "MAILSLOT", "MIDI IN", "MIDI OUT", "MOUSE", "UNC PROVIDER", "NAMED PIPE",
      "NETWORK", "NETWORK BROWSER", "NETWORK FILE SYSTEM", "NULL", "PARALLEL PORT",
      "PHYSICAL NETCARD", "PRINTER", "SCANNER", "SERIAL MOUSE PORT", "SERIAL PORT",
      "SCREEN", "SOUND", "STREAMS", "TAPE", "TAPE FILE SYSTEM", "TRANSPORT", "UNKNOWN",
      "VIDEO", "VIRTUAL DISK", "WAVE IN", "WAVE OUT", "8042 PORT", "NETWORK REDIRECTOR",
      "BATTERY", "BUS EXTENDER", "MODEM", "VDM"
    ]

    types[device_type]
  end

  def to_unix_time(thi, tlo)
    t = ::Time.at(::Rex::Proto::SMB::Utils.time_smb_to_unix(thi, tlo))
    t.strftime("%m-%d-%Y %H:%M:%S")
  end

  def eval_host(ip, share, subdir = "")
    read = write = false

    # srvsvc adds a null byte that needs to be removed
    share = share.chomp("\x00")

    return false,false,nil,nil if share == 'IPC$'

    self.simple.connect("\\\\#{ip}\\#{share}")

    begin
      device_type = self.simple.client.queryfs_fs_device['device_type']
      unless device_type
        vprint_error("\\\\#{ip}\\#{share}: Error querying filesystem device type")
        return false,false,nil,nil
      end

    rescue ::Rex::Proto::SMB::Exceptions::ErrorCode => e
      err = e.to_s.scan(/The server responded with error: (\w+)/i).flatten[0]
      case err
      when /0xffff0002/
        # 0xffff0002 means that the server can't handle the request for device type
        device_type = -1
      when /STATUS_INVALID_DEVICE_REQUEST/
        return false,false,"Invalid device request"
      when /0x00040002/
        # Samba may throw this error too
        return false,false,"Mac/Apple Clipboard?"
      when /STATUS_NETWORK_ACCESS_DENIED/, /0x00030001/, /0x00060002/
        # 0x0006002 = bad network name, 0x0030001 Directory not found
        return false,false,nil,nil
      else
        vprint_error("\\\\#{ip}\\#{share}: Error querying filesystem device type")
        return false,false,nil,nil
      end
    end

    skip = false
    msg = ''
    case device_type
    when -1
      msg = "Unable to determine device"
    when 1, 21 .. 29, 34 .. 35, 37 .. 44
      skip = true
      msg = "Unhandled Device Type (#{device_type})"
    when 2 .. 16, 18 .. 20, 30 .. 33, 36
      msg = device_type_int_to_text(device_type)
    when 17
      skip = true
      msg = device_type_int_to_text(device_type)
    else
      msg = "Unknown Device Type"
      msg << " (#{device_type})" if device_type
    end

    return read,write,msg,nil if skip

    rfd = self.simple.client.find_first("#{subdir}\\*")
    read = true if rfd != nil

    # Test writable
    filename = Rex::Text.rand_text_alpha(rand(8))
    wfd = simple.open("\\#{filename}", 'rwct')
    wfd << Rex::Text.rand_text_alpha(rand(1024))
    wfd.close
    simple.delete("\\#{filename}")
    simple.disconnect("\\\\#{ip}\\#{share}")

    # Operating under assumption STATUS_ACCESS_DENIED or the like will get
    # thrown before write=true
    write = true

    return read,write,msg,rfd

    rescue ::Rex::Proto::SMB::Exceptions::NoReply,::Rex::Proto::SMB::Exceptions::InvalidType,
      ::Rex::Proto::SMB::Exceptions::ReadPacket,::Rex::Proto::SMB::Exceptions::ErrorCode
      return read,false,msg,rfd
  end

  def get_os_info(ip, rport)
    os      = smb_fingerprint
    os_info = "#{os['os']} #{os['sp']} (#{os['lang']})" if os['os'] != "Unknown"
    report_service(
      :host  => ip,
      :port  => rport,
      :proto => 'tcp',
      :name  => 'smb',
      :info  => os_info
    ) if os_info

    os_info
  end

  def get_user_dirs(ip, share, base, sub_dirs)
    dirs = []
    usernames = []

    begin
      read,write,type,files = eval_host(ip, share, base)
      # files or type could return nil due to various conditions
      return dirs if files.nil?
      files.each do |f|
        if f[0] != "." and f[0] != ".."
          usernames.push(f[0])
        end
      end
      usernames.each do |username|
        sub_dirs.each do |sub_dir|
          dirs.push("#{base}\\#{username}\\#{sub_dir}")
        end
      end
      return dirs
    rescue
      return dirs
    end
  end

  def profile_options(ip, share)
    old_dirs = ['My Documents','Desktop']
    new_dirs = ['Desktop','Documents','Downloads','Music','Pictures','Videos']

    dirs = get_user_dirs(ip, share, "Documents and Settings", old_dirs)
    if dirs.blank?
      dirs = get_user_dirs(ip, share, "Users", new_dirs)
    end
    return dirs
  end

  def get_files_info(ip, rport, shares, info)
    read  = false
    write = false

    # Creating a separate file for each IP address's results.
    detailed_tbl = Rex::Text::Table.new(
      'Header'  => "Spidered results for #{ip}.",
      'Indent'  => 1,
      'Columns' => [ 'IP Address', 'Type', 'Share', 'Path', 'Name', 'Created', 'Accessed', 'Written', 'Changed', 'Size' ]
    )

    logdata = ""

    list = shares.collect {|e| e[0]}
    list.each do |x|
      x = x.strip
      if x == "ADMIN$" or x == "IPC$"
        next
      end
      if not datastore['ShowFiles']
        print_status("Spidering #{x}.")
      end
      subdirs = [""]
      if x.strip() == "C$" and datastore['SpiderProfiles']
        subdirs = profile_options(ip, x)
      end
      while subdirs.length > 0
        depth = subdirs[0].count("\\")
        if datastore['SpiderProfiles'] and x == "C$"
          if depth-2 > datastore['MaxDepth']
            subdirs.shift
            next
          end
        else
          if depth > datastore['MaxDepth']
            subdirs.shift
            next
          end
        end
        read,write,type,files = eval_host(ip, x, subdirs[0])
        if files and (read or write)
          if files.length < 3
            subdirs.shift
            next
          end
          header = ""
          if simple.client.default_domain and simple.client.default_name
            header << " \\\\#{simple.client.default_domain}"
          end
          header << "\\#{x.sub("C$","C$\\")}" if simple.client.default_name
          header << subdirs[0]

          pretty_tbl = Rex::Text::Table.new(
            'Header'  => header,
            'Indent'  => 1,
            'Columns' => [ 'Type', 'Name', 'Created', 'Accessed', 'Written', 'Changed', 'Size' ]
          )

          f_types = {
            1  => 'RO',  2  => 'HIDDEN', 4  => 'SYS', 8   => 'VOL',
            16 => 'DIR', 32 => 'ARC',    64 => 'DEV', 128 => 'FILE'
          }

          files.each do |file|
            if file[0] and file[0] != '.' and file[0] != '..'
              info  = file[1]['info']
              fa    = f_types[file[1]['attr']]       # Item type
              fname = file[0]                        # Filename
              tcr   = to_unix_time(info[3], info[2]) # Created
              tac   = to_unix_time(info[5], info[4]) # Accessed
              twr   = to_unix_time(info[7], info[6]) # Written
              tch   = to_unix_time(info[9], info[8]) # Changed
              sz    = info[12] + info[13]            # Size

              # Filename is too long for the UI table, cut it.
              fname = "#{fname[0, 35]}..." if fname.length > 35

              # Add subdirectories to list to use if SpiderShare is enabled.
              if fa == "DIR" or (fa == nil and sz == 0)
                subdirs.push(subdirs[0] + "\\" + fname)
              end

              pretty_tbl << [fa || 'Unknown', fname, tcr, tac, twr, tch, sz]
              detailed_tbl << ["#{ip}", fa || 'Unknown', "#{x}", subdirs[0] + "\\", fname, tcr, tac, twr, tch, sz]
              logdata << "#{ip}\\#{x.sub("C$","C$\\")}#{subdirs[0]}\\#{fname}\n"

            end
          end
          print_good(pretty_tbl.to_s) if datastore['ShowFiles']
        end
        subdirs.shift
      end
    print_status("Spider #{x} complete.") unless datastore['ShowFiles']
    end
    unless detailed_tbl.rows.empty?
      if datastore['LogSpider'] == '1'
        p = store_loot('smb.enumshares', 'text/csv', ip, detailed_tbl.to_csv)
        print_good("info saved in: #{p.to_s}")
      elsif datastore['LogSpider'] == '2'
        p = store_loot('smb.enumshares', 'text/plain', ip, detailed_tbl)
        print_good("info saved in: #{p.to_s}")
      elsif datastore['LogSpider'] == '3'
        p = store_loot('smb.enumshares', 'text/plain', ip, logdata)
        print_good("info saved in: #{p.to_s}")
      end
    end
  end

  def rport
    @rport || datastore['RPORT']
  end

  # Overrides the one in smb.rb
  def smb_direct
    @smb_redirect || datastore['SMBDirect']
  end

  def run_host(ip)
    @rport        = datastore['RPORT']
    @smb_redirect = datastore['SMBDirect']
    @srvsvc       = datastore['USE_SRVSVC_ONLY']
    shares        = []

    [[139, false], [445, true]].each do |info|
      @rport        = info[0]
      @smb_redirect = info[1]

      begin
        connect(versions: [2,1])
        smb_login
        shares = smb_netshareenumall

        os_info     = get_os_info(ip, rport)
        print_status(os_info) if os_info

        if shares.empty?
          print_status("No shares collected")
        else
          shares_info = shares.map{|x| "#{x[0]} - (#{x[1]}) #{x[2]}" }.join(", ")
          shares_info.split(", ").each { |share|
            print_good share
          }
          report_note(
            :host   => ip,
            :proto  => 'tcp',
            :port   => rport,
            :type   => 'smb.shares',
            :data   => { :shares => shares },
            :update => :unique_data
          )

          if datastore['SpiderShares']
            get_files_info(ip, rport, shares, info)
          end

          break if rport == 139
        end

      rescue ::Interrupt
        raise $!
      rescue ::Rex::Proto::SMB::Exceptions::LoginError,
        ::Rex::Proto::SMB::Exceptions::ErrorCode => e
        print_error(e.message)
        return if e.message =~ /STATUS_ACCESS_DENIED/
      rescue Errno::ECONNRESET,
        ::Rex::Proto::SMB::Exceptions::InvalidType,
        ::Rex::Proto::SMB::Exceptions::ReadPacket,
        ::Rex::Proto::SMB::Exceptions::InvalidCommand,
        ::Rex::Proto::SMB::Exceptions::InvalidWordCount,
        ::Rex::Proto::SMB::Exceptions::NoReply => e
        vprint_error(e.message)
        next if not shares.empty? and rport == 139 # no results, try again
      rescue Errno::ENOPROTOOPT
        print_status("Wait 5 seconds before retrying...")
        select(nil, nil, nil, 5)
        retry
      rescue ::Exception => e
        next if e.to_s =~ /execution expired/
        next if not shares.empty? and rport == 139
        vprint_error("Error: '#{ip}' '#{e.class}' '#{e.to_s}'")
      ensure
        disconnect
      end

      # if we already got results, not need to try on another port
      return unless shares.empty?
    end
  end
end

