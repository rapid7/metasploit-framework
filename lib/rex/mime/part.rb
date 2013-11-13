# -*- coding: binary -*-
module Rex
module MIME
class Part

  require 'rex/mime/header'
  require 'rex/mime/encoding'

  include Rex::MIME::Encoding

  attr_accessor :header, :content

  def initialize
    self.header = Rex::MIME::Header.new
    self.content = ''
  end

  def to_s
    self.header.to_s + "\r\n" + content_encoded + "\r\n"
  end

  # Returns the part content with any necessary encoding or transformation
  # applied.
  #
  # @return [String] Content with encoding or transformations applied.
  def content_encoded
    binary_content? ? content : force_crlf(content)
  end

  # Answers if the part content is binary.
  #
  # @return [Boolean] true if the part content is binary, false otherwise.
  def binary_content?
    transfer_encoding && transfer_encoding == 'binary'
  end

  # Returns the Content-Transfer-Encoding of the part.
  #
  # @returns [nil] if the part hasn't Content-Transfer-Encoding.
  # @returns [String] The Content-Transfer-Encoding or the part.
  def transfer_encoding
    h = header.find('Content-Transfer-Encoding')
    return nil if h.nil?

    h[1]
  end

end
end
end
