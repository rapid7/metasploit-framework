# -*- coding: binary -*-

require 'addressable'

module Msf
  ###
  #
  # Parses the RHOSTS datastore value, and yields the possible combinations of datastore values
  # that exist for each host
  #
  ###
  class RhostsWalker
    SUPPORTED_SCHEMAS = %w[
      cidr
      file
      http
      https
      mysql
      postgres
      smb
      ssh
    ].freeze
    private_constant :SUPPORTED_SCHEMAS

    ###
    # An error which additionally keeps track of a particular rhost substring which resulted in an error when enumerating
    # the provided rhost string
    ###
    class Error < StandardError
      attr_reader :value, :cause

      def initialize(value, msg = "Unexpected rhost value: #{value.inspect}", cause: nil)
        super(msg)
        @value = value
        @cause = cause
        set_backtrace(cause.backtrace) if cause
      end
    end

    class InvalidSchemaError < StandardError
    end

    class InvalidCIDRError < StandardError
    end

    def initialize(value = '', datastore = Msf::ModuleDataStore.new(nil))
      @value = value
      @datastore = datastore
    end

    #
    # Iterate over the valid rhosts datastores. This can be combined Calling `#valid?` beforehand to ensure
    # that there are no invalid configuration values, as they will be ignored by this method.
    #
    # @yield [Msf::DataStore] Yields only _valid_ rhost values.
    def each(&block)
      return unless @value
      return unless block_given?

      parse(@value, @datastore).each do |result|
        block.call(result) if result.is_a?(Msf::DataStore)
      end

      nil
    end

    # Count the _valid_ datastore permutations for the current rhosts value. This count will
    # ignore any invalid values.
    #
    # @return [Integer]
    def count
      to_enum.count
    end

    #
    # Retrieve the list of errors associated with this rhosts walker
    # @yield [Msf::RhostsWalker::Error] Yields only invalid rhost values.
    def errors(&block)
      return unless @value
      return unless block_given?

      parse(@value, @datastore).each do |result|
        block.call(result) if result.is_a?(Msf::RhostsWalker::Error)
      end

      nil
    end

    #
    # Indicates that the rhosts value is valid and iterable
    #
    # @return [Boolean] True if all items are valid, and there are at least some items present to iterate over. False otherwise.
    def valid?
      parsed_values = parse(@value, @datastore)
      parsed_values.all? { |result| result.is_a?(Msf::DataStore) } && parsed_values.count > 0
    rescue StandardError => e
      elog('rhosts walker invalid', error: e)
      false
    end

    #
    # Parses the input rhosts string, and yields the possible combinations of datastore values.
    #
    # @param value [String] the rhost string
    # @param datastore [Msf::Datastore] the datastore
    # @return [Enumerable<Msf::DataStore|StandardError>] The calculated datastore values that can be iterated over for
    #   enumerating the given rhosts, or the error that occurred when iterating over the input
    def parse(value, datastore)
      Enumerator.new do |results|
        # extract the individual elements from the rhost string, ensuring that
        # whitespace, strings, escape characters, etc are handled correctly.
        values = Rex::Parser::Arguments.from_s(value)
        values.each do |value|
          if (value =~ %r{^file://(.*)}) || (value =~ /^file:(.*)/)
            file = Regexp.last_match(1)
            File.read(file).each_line(chomp: true) do |line|
              parse(line, datastore).each do |result|
                results << result
              end
            end
          elsif value =~ /^cidr:(.*)/
            cidr, child_value = Regexp.last_match(1).split(':', 2)
            # Validate cidr syntax matches ipv6 '%scope_id/mask_part' or ipv4 '/mask_part'
            raise InvalidCIDRError unless cidr =~ %r{^(%\w+)?/\d{1,3}$}

            # Parse the values, then apply range walker over the result
            parse(child_value, datastore).each do |result|
              host_with_cidr = result['RHOSTS'] + cidr
              Rex::Socket::RangeWalker.new(host_with_cidr).each_ip do |rhost|
                results << result.merge('RHOSTS' => rhost, 'UNPARSED_RHOSTS' => value)
              end
            end
          elsif value =~ /^(?<schema>\w+):.*/ && SUPPORTED_SCHEMAS.include?(Regexp.last_match(:schema))
            schema = Regexp.last_match(:schema)
            raise InvalidSchemaError unless SUPPORTED_SCHEMAS.include?(schema)

            parse_method = "parse_#{schema}_uri"
            parsed_options = send(parse_method, value, datastore)
            Rex::Socket::RangeWalker.new(parsed_options['RHOSTS']).each_ip do |ip|
              results << datastore.merge(
                parsed_options.merge('RHOSTS' => ip, 'UNPARSED_RHOSTS' => value)
              )
            end
          else
            Rex::Socket::RangeWalker.new(value).each_host do |rhost|
              overrides = {}
              overrides['UNPARSED_RHOSTS'] = value
              overrides['RHOSTS'] = rhost[:address]
              overrides['VHOST'] = rhost[:hostname] if datastore.options.include?('VHOST') && datastore['VHOST'].blank?
              results << datastore.merge(overrides)
            end
          end
        rescue StandardError => e
          results << Msf::RhostsWalker::Error.new(value, cause: e)
        end
      end
    end

    # Parses a string such as smb://domain;user:pass@domain/share_name/file.txt into a hash which can safely be
    # merged with a [Msf::DataStore] datastore for setting smb options.
    #
    # @param value [String] the http string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the smb uri value
    def parse_smb_uri(value, datastore)
      uri = ::Addressable::URI.parse(value)
      result = {}

      result['RHOSTS'] = uri.hostname
      result['RPORT'] = (uri.port || 445) if datastore.options.include?('RPORT')

      # Handle users in the format:
      #   user
      #   domain;user
      if uri.user && uri.user.include?(';')
        domain, user = uri.user.split(';')
        result['SMBDomain'] = domain
        result['SMBUser'] = user
        set_username(datastore, result, user)
      elsif uri.user
        set_username(datastore, result, uri.user)
      end
      set_password(datastore, result, uri.password) if uri.password

      # Handle paths of the format:
      #    /
      #    /share_name
      #    /share_name/file
      #    /share_name/dir/file
      has_path_specified = !uri.path.blank? && uri.path != '/'
      if has_path_specified
        _preceding_slash, share, *rpath = uri.path.split('/')
        result['SMBSHARE'] = share if datastore.options.include?('SMBSHARE')
        result['RPATH'] = rpath.join('/') if datastore.options.include?('RPATH')
      end

      result
    end

    # Parses a string such as http://example.com into a hash which can safely be
    # merged with a [Msf::DataStore] datastore for setting http options.
    #
    # @param value [String] the http string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the uri value
    def parse_http_uri(value, datastore)
      uri = ::Addressable::URI.parse(value)
      result = {}
      # nil VHOST for now, this value will be calculated and overridden later
      result['VHOST'] = nil

      result['RHOSTS'] = uri.hostname
      is_ssl = %w[ssl https].include?(uri.scheme)
      result['RPORT'] = uri.port || (is_ssl ? 443 : 80)
      result['SSL'] = is_ssl

      # Both `TARGETURI` and `URI` are used as datastore options to denote the path on a uri
      has_path_specified = !uri.path.blank? # && uri.path != '/' - Note HTTP path parsing differs to the other protocol's parsing
      if has_path_specified
        target_uri = uri.path.present? ? uri.path : '/'
        result['TARGETURI'] = target_uri if datastore.options.include?('TARGETURI')
        result['PATH'] = target_uri if datastore.options.include?('PATH')
        result['URI'] = target_uri if datastore.options.include?('URI')
      end

      result['VHOST'] = uri.hostname unless Rex::Socket.is_ip_addr?(uri.hostname)
      set_username(datastore, result, uri.user) if uri.user
      set_password(datastore, result, uri.password) if uri.password

      result
    end
    alias parse_https_uri parse_http_uri

    # Parses a uri string such as mysql://user:password@example.com into a hash
    # which can safely be merged with a [Msf::DataStore] datastore for setting mysql options.
    #
    # @param value [String] the uri string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the uri value
    def parse_mysql_uri(value, datastore)
      uri = ::Addressable::URI.parse(value)
      result = {}

      result['RHOSTS'] = uri.hostname
      result['RPORT'] = uri.port || 3306

      has_database_specified = !uri.path.blank? && uri.path != '/'
      if datastore.options.include?('DATABASE') && has_database_specified
        result['DATABASE'] = uri.path[1..-1]
      end

      set_username(datastore, result, uri.user) if uri.user
      set_password(datastore, result, uri.password) if uri.password
      result
    end

    # Parses a uri string such as postgres://user:password@example.com into a hash
    # which can safely be merged with a [Msf::DataStore] datastore for setting mysql options.
    #
    # @param value [String] the uri string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the uri value
    def parse_postgres_uri(value, datastore)
      uri = ::Addressable::URI.parse(value)
      result = {}

      result['RHOSTS'] = uri.hostname
      result['RPORT'] = uri.port || 5432

      has_database_specified = !uri.path.blank? && uri.path != '/'
      if datastore.options.include?('DATABASE') && has_database_specified
        result['DATABASE'] = uri.path[1..-1]
      end
      set_username(datastore, result, uri.user) if uri.user
      set_password(datastore, result, uri.password) if uri.password

      result
    end

    # Parses a uri string such as ssh://user:password@example.com into a hash
    # which can safely be merged with a [Msf::DataStore] datastore for setting mysql options.
    #
    # @param value [String] the uri string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the uri value
    def parse_ssh_uri(value, datastore)
      uri = ::Addressable::URI.parse(value)
      result = {}

      result['RHOSTS'] = uri.hostname
      result['RPORT'] = uri.port || 22

      set_username(datastore, result, uri.user) if uri.user
      set_password(datastore, result, uri.password) if uri.password

      result
    end

    protected

    def set_username(datastore, result, username)
      # Preference setting application specific values first
      username_set = false
      option_names = %w[SMBUser FtpUser Username user USERNAME username]
      option_names.each do |option_name|
        if datastore.options.include?(option_name)
          result[option_name] = username
          username_set = true
        end
      end

      # Only set basic auth HttpUsername as a fallback
      if !username_set && datastore.options.include?('HttpUsername')
        result['HttpUsername'] = username
      end

      result
    end

    def set_password(datastore, result, password)
      # Preference setting application specific values first
      password_set = false
      password_option_names = %w[SMBPass FtpPass Password pass PASSWORD password]
      password_option_names.each do |option_name|
        if datastore.options.include?(option_name)
          result[option_name] = password
          password_set = true
        end
      end

      # Only set basic auth HttpPassword as a fallback
      if !password_set && datastore.options.include?('HttpPassword')
        result['HttpPassword'] = password
      end

      result
    end
  end
end
