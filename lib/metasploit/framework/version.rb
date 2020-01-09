require 'rbconfig'
require 'yaml'

module Metasploit
  module Framework
    module Version
      # Determines the git hash for this source tree
      #
      # @return [String] the git hash for this source tree
      def self.get_hash
        @@git_hash ||= begin
          root = File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..'))
          version_yml = File.join(root, 'version.yml')
          hash = ''

          if File.exist?(version_yml)
            version_info = YAML.load_file(version_yml)
            hash = '-' + version_info['build_framework_rev']
          else
            # determine if git is installed
            null = RbConfig::CONFIG['host_os'] =~ /mswin|mingw/ ? 'NUL' : '/dev/null'
            git_installed = system("git --version > #{null} 2>&1")

            # get the hash of the HEAD commit
            if git_installed && File.exist?(File.join(root, '.git'))
              hash = '-' + `git rev-parse --short HEAD`
            end
          end
          hash.strip
        end
      end

      VERSION = "5.0.69"
      MAJOR, MINOR, PATCH = VERSION.split('.').map { |x| x.to_i }
      PRERELEASE = 'dev'
      HASH = get_hash
    end

    VERSION = "#{Version::VERSION}-#{Version::PRERELEASE}#{Version::HASH}"
    GEM_VERSION = "#{Version::VERSION}"
  end
end
