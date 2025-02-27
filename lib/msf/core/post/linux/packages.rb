# -*- coding: binary -*-

module Msf
  class Post
    module Linux
      module Packages
        include ::Msf::Post::Linux::System

        #
        # Determines the version of an installed package
        #
        # @param package The package name to check for
        # @return [Rex::Version] nil if OS is not supported or package is not installed
        #
        def installed_package_version(package)
          info = get_sysinfo

          if ['debian', 'ubuntu'].include?(info[:distro])
            package_version = cmd_exec("dpkg-query -f='${Version}' -W #{package}")
            # The "no package" error is language based, but "dpkg-query:" starting is not
            return nil if package_version.start_with?('dpkg-query:')

            package_version = package_version.gsub('+', '.')
            return Rex::Version.new(package_version)
          elsif ['redhat', 'fedora', 'centos'].include?(info[:distro])
            package_version = cmd_exec("rpm -q #{package}")
            return nil unless package_version.start_with?(package)

            # dnf-4.18.0-2.fc39.noarch
            # remove package name at the beginning
            package_version = package_version.split("#{package}-")[1]
            # remove arch at the end
            package_version = package_version.sub(/\.[^.]*$/, '')
            return Rex::Version.new(package_version)
          elsif ['solaris', 'oracle', 'freebsd'].include?(info[:distro])
            package_version = cmd_exec("pkg info #{package}")
            return nil unless package_version.include?('Version')

            package_version = package_version.match(/Version\s+:\s+(.+)/)[1]
            return Rex::Version.new(package_version)
          elsif ['gentoo'].include?(info[:distro])
            # https://wiki.gentoo.org/wiki/Equery
            if command_exists?('equery')
              package_version = cmd_exec("equery --quiet list #{package}")
            # https://wiki.gentoo.org/wiki/Q_applets
            elsif command_exists?('qlist')
              package_version = cmd_exec("qlist -Iv #{package}")
            else
              vprint_error("installed_package_version couldn't find qlist and equery on gentoo")
              return nil
            end
            return nil if package_version.strip.empty?

            package_version = package_version.split('/')[1]
            # make gcc-1.1 to 1.1
            package_version = package_version.sub(/.*?-/, '')
            return Rex::Version.new(package_version)
          elsif ['arch'].include?(info[:distro])
            package_version = cmd_exec("pacman -Qi #{package}")
            return nil unless package_version.include?('Version')

            package_version = package_version.match(/Version\s+:\s+(.+)/)[1]
            return Rex::Version.new(package_version)
          else
            vprint_error("installed_package_version is being called on an unsupported OS: #{info[:distro]}")
          end
          nil
        end
      end
    end
  end
end
