module Octokit

  # Class to parse and create Gist URLs
  class Gist

    # !@attribute id
    #   @return [String] Gist ID
    attr_accessor :id

    # Instantiate {Gist} object from Gist URL
    # @ return [Gist]
    def self.from_url(url)
      Gist.new(URI.parse(url).path[1..-1])
    end

    def initialize(gist)
      case gist
      when Integer, String
        @id = gist.to_s
      end
    end

    # Gist ID
    # @return [String]
    def to_s
      @id
    end

    # Gist URL
    # @return [String]
    def url
      "https://gist.github.com/#{@id}"
    end

  end
end
