# -*- coding: binary -*-
module Rex
module MIME
class Part

  require 'rex/mime/header'

  attr_accessor :header, :content

  def initialize
    self.header = Rex::MIME::Header.new
    self.content = ''
  end

  def to_s
    self.header.to_s + "\r\n" + self.content + "\r\n"
  end

end
end
end
