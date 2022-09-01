module Metasploit
  module Framework
    module Ssh
      module Platform
        def self.get_platform(ssh_socket)
          info = get_platform_info(ssh_socket, timeout: 10)
          get_platform_from_info(info)
        end

        def self.get_platform_info(ssh_socket, timeout: 10)
          info = ''
          begin
            Timeout.timeout(timeout) do
              info = ssh_socket.exec!("id\n").to_s
              if (info =~ /id=/)
                info << ssh_socket.exec!("uname -a\n").to_s
                if (info =~ /JUNOS /)
                  # We're in the SSH shell for a Juniper JunOS, we can pull the version from the cli
                  # line 2 is hostname, 3 is model, 4 is the Base OS version
                  info = ssh_socket.exec!("cli show version\n").split("\n")[2..4].join(', ').to_s
                elsif (info =~ /Linux USG /)
                  # Ubiquiti Unifi USG
                  info << ssh_socket.exec!("cat /etc/version\n").to_s.rstrip
                end
                temp_proof = ssh_socket.exec!("grep unifi.version /tmp/system.cfg\n").to_s.rstrip
                if (temp_proof =~ /unifi\.version/)
                  info << temp_proof
                  # Ubiquiti Unifi device (non-USG), possibly a switch.  Tested on US-24, UAP-nanoHD
                  # The /tmp/*.cfg files don't give us device info, however the info command does
                  # we dont call it originally since it doesnt say unifi/ubiquiti in it and info
                  # is a linux command as well
                  info << ssh_socket.exec!("grep board.name /etc/board.info\n").to_s.rstrip
                end
              elsif info =~ /Unknown command or computer name/
                # Cisco IOS
                info = ssh_socket.exec!("ver\n").to_s
                # Juniper ScreenOS
              elsif info =~ /unknown keyword/
                info = ssh_socket.exec!("get chassis\n").to_s
                # Juniper JunOS CLI
              elsif info =~ /unknown command: id/
                info = ssh_socket.exec!("show version\n").split("\n")[2..4].join(', ').to_s
                # Brocade CLI
              elsif info =~ /Invalid input -> id/ || info =~ /Protocol error, doesn't start with scp!/
                info = ssh_socket.exec!("show version\n").to_s
                if info =~ /Version:(?<os_version>.+).+HW: (?<hardware>)/mi
                  info = "Model: #{hardware}, OS: #{os_version}"
                end
                # Arista
              elsif info =~ /% Invalid input at line 1/
                info = ssh_socket.exec!("show version\n").split("\n")[0..1]
                info = info.map { |item| item.strip }
                info = info.join(', ').to_s
                # Windows
              elsif info =~ /command not found|is not recognized as an internal or external command/
                info = ssh_socket.exec!("systeminfo\n").to_s
                /OS Name:\s+(?<os_name>.+)$/ =~ info
                /OS Version:\s+(?<os_num>.+)$/ =~ info
                if os_num.present? && os_name.present?
                  info = "#{os_name.strip} #{os_num.strip}"
                else
                  info = ssh_socket.exec!("ver\n").to_s.strip
                end
                # mikrotik
              elsif info =~ /bad command name id \(line 1 column 1\)/
                info = ssh_socket.exec!("/ system resource print\n").to_s
                /platform:\s+(?<platform>.+)$/ =~ info
                /board-name:\s+(?<board>.+)$/ =~ info
                /version:\s+(?<version>.+)$/ =~ info
                if version && platform && board
                  info = "#{platform.strip} #{board.strip} #{version.strip}"
                end
                # esxi 6.7
              elsif info =~ /sh: id: not found/
                info = ssh_socket.exec!("vmware -v\n").to_s
              else
                info << ssh_socket.exec!("help\n?\n\n\n").to_s
              end
            end
          rescue Timeout::Error
          end

          info
        end

        def self.get_platform_from_info(info)
          case info
          when /unifi\.version|UniFiSecurityGateway/i # Ubiquiti Unifi.  uname -a is left in, so we got to pull before Linux
            'unifi'
          when /Linux/i
            'linux'
          when /VMware ESXi/i
            'linux'
          when /Darwin/i
            'osx'
          when /SunOS/i
            'solaris'
          when /BSD/i
            'bsd'
          when /HP-UX/i
            'hpux'
          when /AIX/i
            'aix'
          when /cygwin|Win32|Windows|Microsoft/i
            'windows'
          when /Unknown command or computer name|Line has invalid autocommand/i
            'cisco-ios'
          when /unknown keyword/i # ScreenOS
            'juniper'
          when /JUNOS Base OS/i # JunOS
            'juniper'
          when /MikroTik/i
            'mikrotik'
          when /Arista/i
            'arista'
          else
            'unknown'
          end
        end
      end
    end
  end
end
