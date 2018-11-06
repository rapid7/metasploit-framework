module Recog

# A collection of {Fingerprint fingerprints} for matching against a particular
# kind of fingerprintable data, e.g. an HTTP `Server` header
class DB
  require 'nokogiri'
  require 'recog/fingerprint'

  # @return [String]
  attr_reader :path

  # @return [Array<Fingerprint>] {Fingerprint} objects that can be matched
  #   against strings that make sense for the {#match_key}
  attr_reader :fingerprints

  # @return [String] Taken from the `fingerprints/matches` attribute, or
  #   defaults to the basename of {#path} without the `.xml` extension.
  attr_reader :match_key

  # @return [String] Taken from the `fingerprints/protocol` attribute, or
  #   defaults to an empty string
  attr_reader :protocol

  # @return [String] Taken from the `fingerprints/database_type` attribute
  #   defaults to an empty string
  attr_reader :database_type

  # @return [Float] Taken from the `fingerprints/preference` attribute,
  #   defaults to 0.10.  Used when ordering databases, highest numbers
  #   are given priority and are processed first.
  attr_reader :preference

  # Default Fingerprint database preference when it isn't specified in file
  # Do not use a value below 0.10 so as to allow users to specify lower
  # values in their own custom XML that will always run last.
  DEFAULT_FP_PREFERENCE = 0.10

  # @param path [String]
  def initialize(path)
    @match_key = nil
    @protocol = ''
    @database_type = ''
    @preference = DEFAULT_FP_PREFERENCE.to_f
    @path = path
    @fingerprints = []

    parse_fingerprints
  end

  # @return [void]
  def parse_fingerprints
    xml = nil

    File.open(self.path, 'rb') do |fd|
      xml = Nokogiri::XML(fd.read(fd.stat.size))
    end

    raise "#{self.path} is invalid XML: #{xml.errors.join(',')}" unless xml.errors.empty?

    xml.xpath('/fingerprints').each do |fbase|

      @match_key = fbase['matches'].to_s if fbase['matches']
      @protocol = fbase['protocol'].to_s if fbase['protocol']
      @database_type = fbase['database_type'].to_s if fbase['database_type']
      @preference = fbase['preference'].to_f if fbase['preference']

    end

    @match_key = File.basename(self.path).sub(/\.xml$/, '') unless @match_key

    xml.xpath('/fingerprints/fingerprint').each do |fprint|
      @fingerprints << Fingerprint.new(fprint, @match_key, @protocol)
    end

    xml = nil
  end
end
end
