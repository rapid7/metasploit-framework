module Nexpose

  class GlobalBlackout < APIObject
    require 'json'
    include JsonSerializer

    # [Array] Blackout starting dates, times and duration for blackout periods.
    attr_accessor :blackout

    def initialize(blackout)
      @blackout = Array(blackout)
    end

    def save(nsc)
      params = to_json
      AJAX.post(nsc, '/api/2.1/silo_blackout/', params, AJAX::CONTENT_TYPE::JSON)
    end

    def to_h
      {
        blackouts: (@blackout || []).map(&:to_h)
      }
    end

    def to_json
      JSON.generate(to_h)
    end

    def self.json_initializer(data)
      new(blackout: data)
    end

    def self.load(nsc)
      uri               = '/api/2.1/silo_blackout/'
      resp              = AJAX.get(nsc, uri, AJAX::CONTENT_TYPE::JSON)
      hash              = JSON.parse(resp, symbolize_names: true)
      blackout          = self.json_initializer(hash).deserialize(hash)
      blackout.blackout = (hash[:blackouts] || []).map { |bout| Nexpose::Blackout.from_hash(bout) }
      blackout
    end
  end
end
