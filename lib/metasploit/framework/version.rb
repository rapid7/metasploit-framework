require 'rbconfig'
require 'yaml'
require 'open3'

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
            # Fallback to using Git version detection if version_yml not present
            changed_files = %w[git rev-parse --short HEAD]
            begin
              # stderr may contain Git warnings that we can ignore
              output, _stderr, status = ::Open3.capture3(*changed_files, chdir: root)
              hash = "-#{output}" if status.success?
            rescue => e
              elog(e) if defined?(elog)
            end
          end
          hash.strip
        end
      end

      VERSION = "6.3.38"
      MAJOR, MINOR, PATCH = VERSION.split('.').map { |x| x.to_i }
      PRERELEASE = 'dev'
      HASH = get_hash
    end

    VERSION = "#{Version::VERSION}-#{Version::PRERELEASE}#{Version::HASH}"
    GEM_VERSION = "#{Version::VERSION}"
  end
end
