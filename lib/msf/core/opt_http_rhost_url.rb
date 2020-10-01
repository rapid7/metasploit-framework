# -*- coding: binary -*-

module Msf
  ###
  #
  # RHOST URL option.
  #
  ###
  class OptHTTPRhostURL < OptBase
    def type
      'rhost http url'
    end

    def normalize(value)
      return unless value

      uri = get_uri(value)
      return unless uri

      option_hash = {}
      # Blank this out since we don't know if this new value will have a `VHOST` to ensure we remove the old value
      option_hash['VHOST'] = nil

      option_hash['RHOSTS'] = uri.hostname
      option_hash['RPORT'] = uri.port
      option_hash['SSL'] = %w[ssl https].include?(uri.scheme)

      # Both `TARGETURI` and `URI` are used as datastore options to denote the path on a uri
      option_hash['TARGETURI'] = uri.path.present? ? uri.path : '/'
      option_hash['URI'] = option_hash['TARGETURI']

      if uri.scheme && %(http https).include?(uri.scheme)
        option_hash['VHOST'] = uri.hostname unless Rex::Socket.is_ip_addr?(uri.hostname)
        option_hash['HttpUsername'] = uri.user.to_s
        option_hash['HttpPassword'] = uri.password.to_s
      end

      option_hash
    end

    def valid?(value, check_empty: false)
      return true unless value || required

      uri = get_uri(value)
      return false unless uri && !uri.host.nil? && !uri.port.nil?

      super
    end

    def calculate_value(datastore)
      return unless datastore['RHOSTS']
      begin
        uri_type = datastore['SSL'] ? URI::HTTPS : URI::HTTP
        uri = uri_type.build(host: datastore['RHOSTS'])
        uri.port = datastore['RPORT']
        # The datastore uses both `TARGETURI` and `URI` to denote the path of a URL, we try both here and fall back to `/`
        uri.path = (datastore['TARGETURI'] || datastore['URI'] || '/')
        uri.user = datastore['HttpUsername']
        uri.password = datastore['HttpPassword'] if uri.user
        uri.to_s
      rescue URI::InvalidComponentError
        nil
      end
    end

    protected

    def get_uri(value)
      return unless value
      return unless single_rhost?(value)

      value = 'http://' + value unless value.start_with?(%r{https?://})
      URI(value)
    rescue URI::InvalidURIError
      nil
    end

    def single_rhost?(value)
      return true if value =~ /[^-0-9,.*\/]/
      walker = Rex::Socket::RangeWalker.new(value)
      return false unless walker.valid?
        # if there is only a single ip then it's not a range
      walker.length == 1
    end

  end
end
