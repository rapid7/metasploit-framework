# -*- coding:binary -*-

module Rex
module Proto
module Nuuo
class Response

  module ParseCode
    Completed = 1
    Partial   = 2
    Error     = 3
  end

  module ParseState
    ProcessingHeader  = 1
    ProcessingBody    = 2
    Completed         = 3
  end

  attr_accessor :headers
  attr_accessor :body
  attr_accessor :protocol
  attr_accessor :status_code
  attr_accessor :message
  attr_accessor :bufq
  attr_accessor :state

  def initialize(buf=nil)
    self.state = ParseState::ProcessingHeader
    self.headers = {}
    self.body = ''
    self.protocol = nil
    self.status_code = nil
    self.message = nil
    self.bufq = ''
    parse(buf) if buf
  end

  # returns state of parsing
  def parse(buf)
    self.bufq << buf

    if self.state == ParseState::ProcessingHeader
      parse_header
    end

    if self.state == ParseState::ProcessingBody
      if self.body_bytes_left == 0
        self.state = ParseState::Completed
      else
        parse_body
      end
    end

    (self.state == ParseState::Completed) ? ParseCode::Completed : ParseCode::Partial
  end

  protected
  attr_accessor :body_bytes_left

  def parse_header
    head,body = self.bufq.split("\r\n\r\n", 2)
    return nil unless body

    get_headers(head)
    self.bufq = body || ''
    self.body_bytes_left = 0

    if self.headers['Content-Length']
      self.body_bytes_left = self.headers['Content-Length'].to_i
    end

    self.state = ParseState::ProcessingBody
  end

  def parse_body
    return if self.bufq.length == 0
    if self.body_bytes_left >= 0
      part = self.bufq.slice!(0, self.body_bytes_left)
      self.body << part
      self.body_bytes_left -= part.length
    else
      self.body_bytes_left = 0
    end

    if self.body_bytes_left == 0
      self.state = ParseState::Completed
    end
  end

  def get_headers(head)
    head.each_line.with_index do |l, i|
      if i == 0
        self.protocol,self.status_code,self.message = l.split(' ', 3)
        self.status_code = self.status_code.to_i if self.status_code
        next
      end
      k,v = l.split(':', 2)
      self.headers[k] = v.strip
    end
  end

end
end
end
end
