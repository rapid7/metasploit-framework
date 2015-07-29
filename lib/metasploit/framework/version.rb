require 'rbconfig'
require 'yaml'

module Metasploit
  module Framework
    module Version

      def self.root_path
        File.expand_path(File.join(File.dirname(__FILE__), '..', '..', '..'))
      end

      def self.git_available?
        @@git_available ||= begin
          # adjust for Windows systems
          void = RbConfig::CONFIG['host_os'] =~ /mswin|mingw/ ? 'NUL' : '/dev/null'
          system("git --version >>#{void} 2>&1") && File.exist?(File.join(root_path, '.git'))
        end
      end

      def self.version_yml
        @@version_yml ||= begin
          path = File.join(root_path, 'version.yml')
          File.exist?(path) ? YAML.load_file(path) : nil
        end
      end

      def self.version
        @@version ||= begin
          v = [4, 11, 4]
          if version_yml
            v = [version_yml['major'].to_i, version_yml['minor'].to_i, version_yml['patch'].to_i]
          else
            matching_tags = `git tag -l "?.*.*-??????????"`
            unless matching_tags.nil?
              tags = matching_tags.split('\n')
              if tags.length > 0
                match = tags[-1].match(/(\d*)\.(\d*)\.(\d*)-\d*/)
                if match && match.length == 4
                  v = [match[1].to_i, match[2].to_i, match[3].to_i]
                end
              end
            end
          end
          v
        end
      end

      def self.get_major
        version[0]
      end

      def self.get_minor
        version[1]
      end

      def self.get_patch
        version[2]
      end

      # Determines the git hash for this source tree
      #
      # @return [String] the git hash for this source tree
      def self.git_hash
        @@git_hash ||= begin
          hash = ''

          if version_yml
            # get the stored hash from version.yml
            hash = '-' + version_yml['build_framework_rev']

          elsif git_available?
            # get the hash of the HEAD commit
            hash = '-' + `git rev-parse HEAD`[0, 8]
          end

          hash.strip
        end
      end

      MAJOR = get_major
      MINOR = get_minor
      PATCH = get_patch
      PRERELEASE = 'dev'
      HASH = git_hash
    end

    VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}-#{Version::PRERELEASE}#{Version::HASH}"
    GEM_VERSION = "#{Version::MAJOR}.#{Version::MINOR}.#{Version::PATCH}"
  end
end
