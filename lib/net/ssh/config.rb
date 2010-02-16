module Net; module SSH

  # The Net::SSH::Config class is used to parse OpenSSH configuration files,
  # and translates that syntax into the configuration syntax that Net::SSH
  # understands. This lets Net::SSH scripts read their configuration (to
  # some extent) from OpenSSH configuration files (~/.ssh/config, /etc/ssh_config,
  # and so forth).
  #
  # Only a subset of OpenSSH configuration options are understood:
  #
  # * Ciphers => maps to the :encryption option
  # * Compression => :compression
  # * CompressionLevel => :compression_level
  # * ConnectTimeout => maps to the :timeout option
  # * ForwardAgent => :forward_agent
  # * GlobalKnownHostsFile => :global_known_hosts_file
  # * HostBasedAuthentication => maps to the :auth_methods option
  # * HostKeyAlgorithms => maps to :host_key option
  # * HostKeyAlias => :host_key_alias
  # * HostName => :host_name
  # * IdentityFile => maps to the :keys option
  # * Macs => maps to the :hmac option
  # * PasswordAuthentication => maps to the :auth_methods option
  # * Port => :port
  # * PreferredAuthentications => maps to the :auth_methods option
  # * RekeyLimit => :rekey_limit
  # * User => :user
  # * UserKnownHostsFile => :user_known_hosts_file
  #
  # Note that you will never need to use this class directly--you can control
  # whether the OpenSSH configuration files are read by passing the :config
  # option to Net::SSH.start. (They are, by default.)
  class Config
    class <<self
      @@default_files = %w(~/.ssh/config /etc/ssh_config /etc/ssh/ssh_config)

      # Returns an array of locations of OpenSSH configuration files
      # to parse by default.
      def default_files
        @@default_files
      end

      # Loads the configuration data for the given +host+ from all of the
      # given +files+ (defaulting to the list of files returned by
      # #default_files), translates the resulting hash into the options
      # recognized by Net::SSH, and returns them.
      def for(host, files=default_files)
        translate(files.inject({}) { |settings, file| load(file, host, settings) })
      end

      # Load the OpenSSH configuration settings in the given +file+ for the
      # given +host+. If +settings+ is given, the options are merged into
      # that hash, with existing values taking precedence over newly parsed
      # ones. Returns a hash containing the OpenSSH options. (See
      # #translate for how to convert the OpenSSH options into Net::SSH
      # options.)
      def load(file, host, settings={})
        file = File.expand_path(file)
        return settings unless File.readable?(file)

        in_match = false
        IO.foreach(file) do |line|
          next if line =~ /^\s*(?:#.*)?$/

          if line =~ /^\s*(\S+)\s*=(.*)$/
            key, value = $1, $2
          else
            key, value = line.strip.split(/\s+/, 2)
          end

          # silently ignore malformed entries
          next if value.nil?

          key.downcase!
          value = $1 if value =~ /^"(.*)"$/

          value = case value.strip
            when /^\d+$/ then value.to_i
            when /^no$/i then false
            when /^yes$/i then true
            else value
            end

          if key == 'host'
            in_match = (host =~ pattern2regex(value))
          elsif in_match
            if key == 'identityfile'
              settings[key] ||= []
              settings[key] << value
            else
              settings[key] = value unless settings.key?(key)
            end
          end
        end

        return settings
      end

      # Given a hash of OpenSSH configuration options, converts them into
      # a hash of Net::SSH options. Unrecognized options are ignored. The
      # +settings+ hash must have Strings for keys, all downcased, and
      # the returned hash will have Symbols for keys.
      def translate(settings)
        settings.inject({}) do |hash, (key, value)|
          case key
          when 'ciphers' then
            hash[:encryption] = value.split(/,/)
          when 'compression' then
            hash[:compression] = value
          when 'compressionlevel' then
            hash[:compression_level] = value
          when 'connecttimeout' then
            hash[:timeout] = value
          when 'forwardagent' then
            hash[:forward_agent] = value
          when 'globalknownhostsfile'
            hash[:global_known_hosts_file] = value
          when 'hostbasedauthentication' then
            if value
              hash[:auth_methods] ||= []
              hash[:auth_methods] << "hostbased"
            end
          when 'hostkeyalgorithms' then
            hash[:host_key] = value.split(/,/)
          when 'hostkeyalias' then
            hash[:host_key_alias] = value
          when 'hostname' then
            hash[:host_name] = value
          when 'identityfile' then
            hash[:keys] = value
          when 'macs' then
            hash[:hmac] = value.split(/,/)
          when 'passwordauthentication'
            if value
              hash[:auth_methods] ||= []
              hash[:auth_methods] << "password"
            end
          when 'port'
            hash[:port] = value
          when 'preferredauthentications'
            hash[:auth_methods] = value.split(/,/)
          when 'pubkeyauthentication'
            if value
              hash[:auth_methods] ||= []
              hash[:auth_methods] << "publickey"
            end
          when 'rekeylimit'
            hash[:rekey_limit] = interpret_size(value)
          when 'user'
            hash[:user] = value
          when 'userknownhostsfile'
            hash[:user_known_hosts_file] = value
          end
          hash
        end
      end

      private

        # Converts an ssh_config pattern into a regex for matching against
        # host names.
        def pattern2regex(pattern)
          pattern = "^" + pattern.to_s.gsub(/\./, "\\.").
            gsub(/\?/, '.').
            gsub(/\*/, '.*') + "$"
          Regexp.new(pattern, true)
        end

        # Converts the given size into an integer number of bytes.
        def interpret_size(size)
          case size
          when /k$/i then size.to_i * 1024
          when /m$/i then size.to_i * 1024 * 1024
          when /g$/i then size.to_i * 1024 * 1024 * 1024
          else size.to_i
          end
        end
    end
  end

end; end