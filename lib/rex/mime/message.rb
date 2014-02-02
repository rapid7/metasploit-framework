# -*- coding: binary -*-
module Rex
module MIME
class Message

  require 'rex/mime/header'
  require 'rex/mime/part'
  require 'rex/text'

  attr_accessor :header, :parts, :bound, :content

  def initialize(data=nil)
    self.header = Rex::MIME::Header.new
    self.parts  = []
    self.bound  = "_Part_#{rand(1024)}_#{rand(0xffffffff)}_#{rand(0xffffffff)}"
    self.content = ''
    if data
      head,body = data.split(/\r?\n\r?\n/, 2)

      self.header.parse(head)
      ctype = self.header.find('Content-Type')

      if ctype and ctype[1] and ctype[1] =~ /multipart\/mixed;\s*boundary=([^\s]+)/
        self.bound = $1

        chunks = body.to_s.split(/--#{self.bound}(--)?\r?\n/)
        self.content = chunks.shift.to_s.gsub(/\s+$/, '')
        self.content << "\r\n" if not self.content.empty?

        chunks.each do |chunk|
          break if chunk == "--"
          head,body = chunk.split(/\r?\n\r?\n/, 2)
          part = Rex::MIME::Part.new
          part.header.parse(head)
          part.content = body.gsub(/\s+$/, '')
          self.parts << part
        end
      else
        self.content = body.to_s.gsub(/\s+$/, '') + "\r\n"
      end
    end
  end

  def to
    (self.header.find('To') || [nil, nil])[1]
  end

  def to=(val)
    self.header.set("To", val)
  end

  def from=(val)
    self.header.set("From", val)
  end

  def from
    (self.header.find('From') || [nil, nil])[1]
  end

  def subject=(val)
    self.header.set("Subject", val)
  end

  def subject
    (self.header.find('Subject') || [nil, nil])[1]
  end

  def mime_defaults
    self.header.set("MIME-Version", "1.0")
    self.header.set("Content-Type", "multipart/mixed; boundary=\"#{self.bound}\"")
    self.header.set("Subject", '') # placeholder
    self.header.set("Date", Time.now.strftime("%a,%e %b %Y %H:%M:%S %z"))
    self.header.set("Message-ID",
      "<"+
      Rex::Text.rand_text_alphanumeric(rand(20)+40)+
      "@"+
      Rex::Text.rand_text_alpha(rand(20)+3)+
      ">"
    )
    self.header.set("From", '')    # placeholder
    self.header.set("To", '')      # placeholder
  end


  def add_part(data='', content_type='text/plain', transfer_encoding="8bit", content_disposition=nil)
    part = Rex::MIME::Part.new

    if (content_disposition)
      part.header.set("Content-Disposition", content_disposition)
    end

    if (content_type)
      part.header.set("Content-Type", content_type)
    end

    if (transfer_encoding)
      part.header.set("Content-Transfer-Encoding", transfer_encoding)
    end

    part.content = data
    self.parts << part
    part
  end

  def add_part_attachment(data, name)
    self.add_part(
      Rex::Text.encode_base64(data, "\r\n"),
      "application/octet-stream; name=\"#{name}\"",
      "base64",
      "attachment; filename=\"#{name}\""
    )
  end


  def add_part_inline_attachment(data, name)
    self.add_part(
      Rex::Text.encode_base64(data, "\r\n"),
      "application/octet-stream; name=\"#{name}\"",
      "base64",
      "inline; filename=\"#{name}\""
    )
  end

  def to_s
    msg = self.header.to_s + "\r\n"

    if self.content and not self.content.empty?
      msg << self.content + "\r\n"
    end

    self.parts.each do |part|
      msg << "--" + self.bound + "\r\n"
      msg << part.to_s + "\r\n"
    end

    if self.parts.length > 0
      msg << "--" + self.bound + "--\r\n"
    end

    # Force CRLF for SMTP compatibility
    msg.gsub("\r", '').gsub("\n", "\r\n")
  end

  def to_form_data
    msg = self.header.to_s + "\r\n"

    if self.content and not self.content.empty?
      msg << self.content + "\r\n"
    end

    self.parts.each do |part|
      msg << "--" + self.bound + "\r\n"
      msg << part.to_s
    end

    if self.parts.length > 0
      msg << "--" + self.bound + "--\r\n"
    end

    msg
  end

end
end
end

