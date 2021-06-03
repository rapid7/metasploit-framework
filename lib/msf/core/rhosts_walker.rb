# -*- coding: binary -*-

module Msf
  ###
  #
  # Parses the RHOSTS datastore value, and yields the possible combinations of datastore values
  # that exist for each host
  #
  ###
  class RhostsWalker

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
    # @param value [String] the http string
    # @param datastore [Msf::Datastore] the datastore
    # @return [Enumerable<Msf::DataStore|StandardError>] The calculated datastore values that can be iterated over for
    #   enumerating the given rhosts, or the error that occurred when iterating over the input
    def parse(value, datastore)
      Enumerator.new do |results|
        values = value.to_s.split(', ').map { |line| line.split(' ') }.flatten
        values.each do |value|
          if (value =~ %r{^file://(.*)}) || (value =~ /^file:(.*)/)
            file = Regexp.last_match(1)
            File.read(file).each_line(chomp: true) do |line|
              parse(line, datastore).each do |result|
                results << result
              end
            end
          elsif value.start_with?('smb:')
            smb_options = parse_smb_uri(value, datastore)
            Rex::Socket::RangeWalker.new(smb_options['RHOSTS']).each_ip do |ip|
              results << datastore.merge(
                smb_options.merge('RHOSTS' => ip, 'TODO_RHOST_SCHEMA_VALUE' => value)
              )
            end
          elsif value.start_with?('http:') || value.start_with?('https:')
            http_options = parse_http_uri(value, datastore)
            Rex::Socket::RangeWalker.new(http_options['RHOSTS']).each_ip do |ip|
              results << datastore.merge(
                http_options.merge('RHOSTS' => ip, 'TODO_RHOST_SCHEMA_VALUE' => value)
              )
            end
          elsif value =~ /^cidr:(.*)/
            range, value = Regexp.last_match(1).split(':', 2)

            # Parse the values, then apply range walker over the result
            parse(value, datastore).each do |result|
              host_with_cidr = result['RHOSTS'] + range
              Rex::Socket::RangeWalker.new(host_with_cidr).each_ip do |rhost|
                results << result.merge('RHOSTS' => rhost, 'TODO_RHOST_SCHEMA_VALUE' => value)
              end
            end
          else
            Rex::Socket::RangeWalker.new(value).each_host do |rhost|
              overrides = {}
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

    # Parses an smb string such as smb://domain;user:pass@domain/share_name/file.txt into a hash which can safely be
    # merged with a [Msf::DataStore] datastore for setting smb options.
    #
    # @param value [String] the http string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the http uri value
    def parse_smb_uri(value, datastore)
      uri = URI.parse(value)
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
      elsif uri.user
        result['SMBUser'] = uri.user
      end
      if uri.password
        result['SMBPass'] = uri.password
      end

      # Handle paths of the format:
      #    /
      #    /share_name
      #    /share_name/file
      #    /share_name/dir/file
      if uri.path
        _preceding_slash, share, *rpath = uri.path.split('/')
        result['SMBSHARE'] = share if datastore.options.include?('SMBSHARE')
        result['RPATH'] = rpath.join('/') if datastore.options.include?('RPATH')
      end

      result
    end

    # Parses an http string such as http://example.com into a hash which can safely be
    # merged with a [Msf::DataStore] datastore for setting http options.
    #
    # @param value [String] the http string
    # @return [Hash] A hash where keys match the required datastore options associated with
    #   the http uri value
    def parse_http_uri(value, datastore)
      uri = URI.parse(value)
      result = {}
      # nil VHOST for now, this value will be calculated and overridden later
      result['VHOST'] = nil

      result['RHOSTS'] = uri.hostname
      result['RPORT'] = uri.port
      result['SSL'] = %w[ssl https].include?(uri.scheme)

      # Both `TARGETURI` and `URI` are used as datastore options to denote the path on a uri
      target_uri = uri.path.present? ? uri.path : '/'
      result['TARGETURI'] = target_uri if datastore.options.include?('TARGETURI')
      result['URI'] = target_uri if datastore.options.include?('URI')

      result['VHOST'] = uri.hostname unless Rex::Socket.is_ip_addr?(uri.hostname)
      result['HttpUsername'] = uri.user if uri.user
      result['HttpPassword'] = uri.password if uri.password

      result
    end
  end
end
