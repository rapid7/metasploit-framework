# -*- coding: binary -*-

module Msf
  ###
  #
  # RHOST URL option.
  #
  ###
  class OptHTTPRhostURL < OptBase
    def type
      'rhost url'
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
      option_hash['TARGETURI'] = uri.path || '/'
      option_hash['URI'] = uri.path || '/'

      if uri.scheme && %(http https).include?(uri.scheme)
        option_hash['VHOST'] = uri.hostname unless Rex::Socket.is_ip_addr?(uri.hostname)
        option_hash['HttpUsername'] = uri.user.to_s
        option_hash['HttpPassword'] = uri.password.to_s
      end

      option_hash
    end

    def valid?(value, check_empty: false)
      return true unless value

      uri = get_uri(value)
      false unless !uri.host.nil? && !uri.port.nil?
      super
    end

    def calculate_value(datastore)
      if datastore['RHOSTS']
        begin
          uri = URI::Generic.build(host: datastore['RHOSTS'])
          uri.port = datastore['RPORT']
          # The datastore uses both `TARGETURI` and `URI` to denote the path of a URL, we try both here and fall back to `/`
          uri.path = (datastore['TARGETURI'] || datastore['URI'] || '/')
          uri.user = datastore['HttpUsername']
          uri.password = datastore['HttpPassword'] if uri.user
          uri.scheme = datastore['SSL'] ? "https" : "http"
          uri
        rescue URI::InvalidComponentError
          nil
        end
      end
    end

    protected

    def get_uri(value)
        value = 'http://' + value unless value.start_with?(/https?:\/\//)
        URI(value)
      rescue URI::InvalidURIError
        nil
    end
  end
end
