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
            return nil if package_version.include?('no packages found')

            package_version = package_version.gsub('+', '.')
            return Rex::Version.new(package_version)
          elsif ['redhat', 'fedora'].include?(info[:distro])
            package_version = cmd_exec("rpm -q #{package}")
            return nil if package_version.include?('is not installed')
          
            # dnf-4.18.0-2.fc39.noarch
            # remove package name at the beginning
            package_version = package_version.split("#{package}-")[1]
            # remove arch at the end
            package_version = package_version.sub(/\.[^.]*$/, '')
            return Rex::Version.new(package_version)
          # XXX not tested on live system
          # https://docs.oracle.com/cd/E23824_01/html/821-1451/gkunu.html
          elsif ['solaris', 'oracle'].include?(info[:distro])
            package_version = cmd_exec("pkg info #{package}")
            return nil unless package_version.include?('State: Installed')
          
            package_version = package_version.match(/Version: (.+)/)[1]
            return Rex::Version.new(package_version)
          elsif ['freebsd'].include?(info[:distro])
            package_version = cmd_exec("pkg info #{package}")
            return nil unless package_version.include?('Version')
          
            package_version = package_version.match(/Version\s+:\s+(.+)/)[1]
            return Rex::Version.new(package_version)
          # XXX not tested on live system            
          elsif ['gentoo'].include?(info[:distro])
            # https://wiki.gentoo.org/wiki/Equery
            package_version = cmd_exec("equery --quiet list #{package}")
            return nil if package_version.include?('No packages found')
          
            package_version = package_version.split('/')[1]
            # make gcc-1.1 to 1.1
            package_version = package_version.sub(/.*?-/, '') 
            return Rex::Version.new(package_version)
          # XXX not tested on live system
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
