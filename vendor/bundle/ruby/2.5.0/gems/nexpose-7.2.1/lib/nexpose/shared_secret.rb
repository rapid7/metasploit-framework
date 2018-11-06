module Nexpose
  # SharedSecret class for pairing engines
  class SharedSecret < APIObject
    attr_reader :key_string
    attr_reader :ttl

    def initialize(console, time_to_live)
      uri  = "/data/admin/global/shared-secret?time-to-live=#{time_to_live}"
      json = JSON.parse(AJAX.put(console, uri))
      self.from_json(json)
    end

    def from_json(json)
      @key_string = json['keyString']
      @ttl        = json['timeToLiveInSeconds']
    end

    def delete(console)
      uri = "/data/admin/global/remove-shared-secret?key-string=#{key_string}"
      AJAX.delete(console, uri)
    end

    def ==(other)
      return false unless self.class == other.class
      return false unless key_string.downcase == other.key_string.downcase
      true
    end
    alias eql? ==
  end

end
