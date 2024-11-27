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
        def installed_package_version?(package)
          info = get_sysinfo

          if ['ubuntu', 'debian'].include? info[:distro]
            package = cmd_exec("dpkg -l #{package} | grep \'^ii\'")
            return nil unless package.start_with?('ii')

            package = package.split(' ')[2]
            package = package.gsub('+', '.')
            return Rex::Version.new(package)
          else
            vprint_error('installed_package_version? is being called on an unsupported OS')
          end
          nil
        end
      end
    end
  end
end
