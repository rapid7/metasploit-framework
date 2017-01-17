require 'metasploit/framework'
require 'msf/base/config'

module Metasploit
  module Framework
    module Database
      #
      # CONSTANTS
      #

      CONFIGURATIONS_PATHNAME_PRECEDENCE = [
          :environment_configurations_pathname,
          :user_configurations_pathname,
          :project_configurations_pathname
      ]

      #
      # Module Methods
      #

      # Returns first configuration pathname from configuration_pathnames or the overridding `:path`.
      #
      # @param options [Hash{Symbol=>String}]
      # @option options [String] :path Path to use instead of first element of configurations_pathnames
      # @return [Pathname] if configuration pathname exists.
      # @return [nil] if configuration pathname does not exist.
      def self.configurations_pathname(options={})
        options.assert_valid_keys(:path)

        path = options[:path]

        if path.present?
          pathname = Pathname.new(path)
        else
          pathname = configurations_pathnames.first
        end

        if !pathname.nil? && pathname.exist?
          pathname
        else
          nil
        end
      end

      # Return configuration pathnames that exist.
      #
      # Returns `Pathnames` in order of precedence
      #
      # 1. {environment_configurations_pathname}
      # 2. {user_configurations_pathname}
      # 3. {project_configurations_pathname}
      #
      # @return [Array<Pathname>]
      def self.configurations_pathnames
        configurations_pathnames = []

        CONFIGURATIONS_PATHNAME_PRECEDENCE.each do |configurations_pathname_message|
          configurations_pathname = public_send(configurations_pathname_message)

          if !configurations_pathname.nil? && configurations_pathname.exist?
            configurations_pathnames << configurations_pathname
          end
        end

        configurations_pathnames
      end

      # Pathname to `database.yml` pointed to by `MSF_DATABASE_CONFIG` environment variable.
      #
      # @return [Pathname] if `MSF_DATABASE_CONFIG` is not blank.
      # @return [nil] otherwise
      def self.environment_configurations_pathname
        msf_database_config = ENV['MSF_DATABASE_CONFIG']

        if msf_database_config.blank?
          msf_database_config = nil
        else
          msf_database_config = Pathname.new(msf_database_config)
        end

        msf_database_config
      end

      # Pathname to `database.yml` for the metasploit-framework project in `config/database.yml`.
      #
      # @return [Pathname]
      def self.project_configurations_pathname
        root = Pathname.new(__FILE__).realpath.parent.parent.parent.parent
        root.join('config', 'database.yml')
      end

      # Pathname to `database.yml` in the user's config directory.
      #
      # @return [Pathname] if the user has a `database.yml` in their config directory (`~/.msf4` by default).
      # @return [nil] if the user does not have a `database.yml` in their config directory.
      def self.user_configurations_pathname
        Pathname.new(Msf::Config.get_config_root).join('database.yml')
      end
    end
  end
end
