# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module System
        include ::Msf::Post::Common
        include ::Msf::Post::File
        include ::Msf::Post::Unix
        include Msf::Auxiliary::Report

        #
        # Returns a Hash containing Distribution Name, Version and Kernel Information
        #
        def get_sysinfo
          system_data = {}
          etc_files = cmd_exec('ls /etc').split
          kernel_version = cmd_exec('uname -a')
          system_data[:kernel] = kernel_version

          # Debian
          if etc_files.include?('debian_version')
            version = read_file('/etc/issue').gsub(/\n|\\n|\\l/, '').strip
            if kernel_version =~ /Ubuntu/
              system_data[:distro] = 'ubuntu'
            else
              system_data[:distro] = 'debian'
            end
            system_data[:version] = version

          # Amazon / CentOS
          elsif etc_files.include?('system-release')
            version = read_file('/etc/system-release').gsub(/\n|\\n|\\l/, '').strip
            if version.include? 'CentOS'
              system_data[:distro] = 'centos'
            elsif version.include? 'Fedora'
              system_data[:distro] = 'fedora'
            else
              system_data[:distro] = 'amazon'
            end
            system_data[:version] = version

          # Alpine
          elsif etc_files.include?('alpine-release')
            version = read_file('/etc/alpine-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'alpine'
            system_data[:version] = version

          # Fedora
          elsif etc_files.include?('fedora-release')
            version = read_file('/etc/fedora-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'fedora'
            system_data[:version] = version

          # Oracle Linux
          elsif etc_files.include?('enterprise-release')
            version = read_file('/etc/enterprise-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'oracle'
            system_data[:version] = version

          # RedHat
          elsif etc_files.include?('redhat-release')
            version = read_file('/etc/redhat-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'redhat'
            system_data[:version] = version

          # Arch
          elsif etc_files.include?('arch-release')
            version = read_file('/etc/arch-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'arch'
            system_data[:version] = version

          # Slackware
          elsif etc_files.include?('slackware-version')
            version = read_file('/etc/slackware-version').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'slackware'
            system_data[:version] = version

          # Mandrake
          elsif etc_files.include?('mandrake-release')
            version = read_file('/etc/mandrake-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'mandrake'
            system_data[:version] = version

          # SuSE
          elsif etc_files.include?('SuSE-release')
            version = read_file('/etc/SuSE-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'suse'
            system_data[:version] = version

          # OpenSUSE
          elsif etc_files.include?('SUSE-brand')
            version = read_file('/etc/SUSE-brand').scan(/^VERSION\s*=\s*([\d.]+)/).flatten.first
            system_data[:distro] = 'suse'
            system_data[:version] = version

          # Gentoo
          elsif etc_files.include?('gentoo-release')
            version = read_file('/etc/gentoo-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'gentoo'
            system_data[:version] = version

          # Openwall
          elsif etc_files.include?('owl-release')
            version = read_file('/etc/owl-release').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'openwall'
            system_data[:version] = version

          # Generic
          elsif etc_files.include?('issue')
            version = read_file('/etc/issue').gsub(/\n|\\n|\\l/, '').strip
            system_data[:distro] = 'linux'
            system_data[:version] = version

          # Others, could be a mismatch like ssh_login to cisco device
          else
            system_data[:distro] = 'linux'
            system_data[:version] = ''

          end

          report_host({
            host: rhost,
            os_name: system_data[:distro],
            os_flavor: system_data[:version]
          })

          system_data
        end

        #
        # Gathers all SUID files on the filesystem.
        # NOTE: This uses the Linux `find` command. It will most likely take a while to get all files.
        # Consider specifying a more narrow find path.
        #
        # @param findpath The path on the system to start searching
        # @return [Array]
        #
        def get_suid_files(findpath = '/')
          cmd_exec("find #{findpath} -perm -4000 -print -xdev").to_s.split("\n").delete_if { |i| i.include? 'Permission denied' }
        rescue StandardError
          raise 'Could not retrieve all SUID files'
        end

        #
        # Gets the $PATH environment variable
        #
        # @return [String]
        #
        def get_path
          cmd_exec('echo $PATH').to_s
        rescue StandardError
          raise 'Unable to determine path'
        end

        #
        # Gets basic information about the system's CPU.
        #
        # @return [Hash]
        #
        def get_cpu_info
          info = {}
          orig = read_file('/proc/cpuinfo').to_s
          cpuinfo = orig.split("\n\n")[0]
          # This is probably a more platform independent way to parse the results (compared to splitting and assigning preset indices to values)
          cpuinfo.split("\n").each do |l|
            info[:speed_mhz] = l.split(': ')[1].to_i if l.include? 'cpu MHz'
            info[:product] = l.split(': ')[1] if l.include? 'model name'
            info[:vendor] = l.split(': ')[1] if l.include? 'vendor_id'
          end
          info[:cores] = orig.split("\n\n").size
          info
        rescue StandardError
          raise 'Could not get CPU information'
        end

        #
        # Gets the hostname of the system
        #
        # @return [String]
        #
        def get_hostname
          hostname =
            if command_exists?('uname')
              cmd_exec('uname -n').to_s
            else
              read_file('/proc/sys/kernel/hostname').to_s.chomp
            end
          report_host({ host: rhost, name: hostname })
          hostname
        rescue StandardError
          raise 'Unable to retrieve hostname'
        end

        #
        # Gets the name of the current shell
        #
        # @return [String]
        #
        def get_shell_name
          if command_exists?('ps')
            cmd_exec('ps -p $$').to_s.split("\n").last.split(' ')[3]
          else
            cmd_exec('echo $0').split('-')[1]
          end
        rescue StandardError
          raise 'Unable to gather shell name'
        end

        #
        # Gets the pid of the current shell
        #
        # @return [String]
        #
        def get_shell_pid
          cmd_exec('echo $$').to_s
        end

        #
        # Checks if the system has gcc installed
        #
        # @return [Boolean]
        #
        def has_gcc?
          command_exists? 'gcc'
        rescue StandardError
          raise 'Unable to check for gcc'
        end

        #
        # Checks if the system has clang installed
        #
        # @return [Boolean]
        #
        def has_clang?
          command_exists? 'clang'
        rescue StandardError
          raise 'Unable to check for clang'
        end

        #
        # Checks if `file_path` is mounted on a noexec mount point
        #
        # @return [Boolean]
        #
        def noexec?(file_path)
          mount = read_file('/proc/mounts').to_s
          mount_path = get_mount_path(file_path)
          mount.lines.each do |l|
            return true if l =~ Regexp.new("#{mount_path} (.*)noexec(.*)")
          end
          false
        rescue StandardError
          raise 'Unable to check for noexec volume'
        end

        #
        # Checks if `file_path` is mounted on a nosuid mount point
        #
        # @return [Boolean]
        #
        def nosuid?(file_path)
          mount = read_file('/proc/mounts').to_s
          mount_path = get_mount_path(file_path)
          mount.lines.each do |l|
            return true if l =~ Regexp.new("#{mount_path} (.*)nosuid(.*)")
          end
          false
        rescue StandardError
          raise 'Unable to check for nosuid volume'
        end

        #
        # Checks for protected hardlinks on the system
        #
        # @return [Boolean]
        #
        def protected_hardlinks?
          read_file('/proc/sys/fs/protected_hardlinks').to_s.strip.eql? '1'
        rescue StandardError
          raise 'Could not determine protected_hardlinks status'
        end

        #
        # Checks for protected symlinks on the system
        #
        # @return [Boolean]
        #
        def protected_symlinks?
          read_file('/proc/sys/fs/protected_symlinks').to_s.strip.eql? '1'
        rescue StandardError
          raise 'Could not determine protected_symlinks status'
        end

        #
        # Gets the version of glibc
        #
        # @return [String]
        #
        def glibc_version
          raise 'glibc is not installed' unless command_exists? 'ldd'
          begin

            cmd_exec('ldd --version').scan(/^ldd\s+\(.*\)\s+([\d.]+)/).flatten.first
          rescue StandardError
            raise 'Could not determine glibc version'
          end
        end

        #
        # Gets the mount point of `filepath`
        #
        # @param [String] filepath The filepath to get the mount point
        # @return [String]
        #
        def get_mount_path(filepath)
          cmd_exec("df \"#{filepath}\" | tail -1").split(' ')[5]
        rescue StandardError
          raise "Unable to get mount path of #{filepath}"
        end

        #
        # Gets all the IP directions of the device
        #
        # @return [Array]
        #
        def ips
          lines = read_file('/proc/net/fib_trie')
          result = []
          previous_line = ''
          lines.each_line do |line|
            if line.include?('/32 host LOCAL')
              previous_line = previous_line.split('-- ')[1].strip
              unless result.include? previous_line
                result.insert(-1, previous_line)
              end
            end
            previous_line = line
          end
          result
        end

        #
        # Gets all the interfaces of the device
        #
        # @return [Array]
        #
        def interfaces
          result = []
          data = cmd_exec('for fn in /sys/class/net/*; do echo $fn; done')
          parts = data.split("\n")
          parts.each do |line|
            line = line.split('/')[-1]
            result.insert(-1, line)
          end
          result
        end

        #
        # Gets all the macs of the device
        #
        # @return [Array]
        #
        def macs
          result = []
          str_macs = cmd_exec('for fn in /sys/class/net/*; do echo $fn; done')
          parts = str_macs.split("\n")
          parts.each do |line|
            rut = line + '/address'
            mac_array = read_file(rut)
            mac_array.each_line do |mac|
              result.insert(-1, mac.strip)
            end
          end
          result
        end

        #
        # Parsing information based on: https://github.com/sensu-plugins/sensu-plugins-network-checks/blob/master/bin/check-netstat-tcp.rb
        # Gets all the listening tcp ports in the device
        #
        # @return [Array]
        #
        def listen_tcp_ports
          ports = []
          content = read_file('/proc/net/tcp')
          content.each_line do |line|
            next unless (m = line.match(/^\s*\d+:\s+(.{8}|.{32}):(.{4})\s+(.{8}|.{32}):(.{4})\s+(.{2})/))

            connection_state = m[5].to_s
            next unless connection_state == '0A'

            connection_port = m[2].to_i(16)
            unless ports.include?(connection_port)
              ports.insert(-1, connection_port)
            end
          end
          ports
        end

        # Parsing information based on: https://github.com/sensu-plugins/sensu-plugins-network-checks/blob/master/bin/check-netstat-tcp.rb
        # Gets all the listening udp ports in the device
        #
        # @return [Array]
        #
        def listen_udp_ports
          ports = []
          content = read_file('/proc/net/udp')
          content.each_line do |line|
            next unless (m = line.match(/^\s*\d+:\s+(.{8}|.{32}):(.{4})\s+(.{8}|.{32}):(.{4})\s+(.{2})/))

            connection_state = m[5].to_s
            next unless connection_state == '07'

            connection_port = m[2].to_i(16)
            if ports.include?(connection_port) == false
              ports.insert(-1, connection_port)
            end
          end
          return ports
        end

        #
        # Determine if system is a container
        #
        # @return [String]
        #
        def get_container_type
          # Checking file paths for solution
          container_type =
            if file?('/.dockerenv') || file?('/.dockerinit')
              'Docker'
            elsif file?('/run/.containerenv')
              'Podman'
            elsif directory?('/dev/lxc')
              'LXC'
            elsif file?('/proc/sys/kernel/osrelease') && read_file('/proc/sys/kernel/osrelease').grep(/WSL|Microsoft/i).any?
              # Check for WSL, as suggested in https://github.com/Microsoft/WSL/issues/423#issuecomment-221627364
              'WSL'
            elsif (cgroup = read_file('/proc/1/cgroup'))
              # Check cgroup on PID 1
              case cgroup.tr("\n", ' ')
              when /docker/i
                return 'Docker'
              when /lxc/i
                return 'LXC'
              else
                return 'Unknown'
              end
            else
              # Check for the "container" environment variable
              case get_env('container')
              when 'lxc'
                return 'LXC'
              when 'systemd-nspawn'
                return 'systemd nspawn'
              when 'podman'
                return 'Podman'
              else
                'Unknown'
              end
            end
          unless container_type == 'Unknown'
            report_host({
              host: rhost,
              virtual_host: container_type
            })
          end
          container_type
        end
      end
    end
  end
end
