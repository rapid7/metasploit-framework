module Rex
module MIME
class Message

	require 'rex/mime/header'
	require 'rex/mime/part'
	require 'rex/text'	

	attr_accessor :header, :parts, :bound, :content

	def initialize
		self.header = Rex::MIME::Header.new
		self.parts  = []
		self.bound  = "_Part_#{rand(1024)}_#{rand(0xffffffff)}_#{rand(0xffffffff)}"
		self.content = ''
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
		part.header.set("Content-Type", content_type)
		
		if (transfer_encoding)
			part.header.set("Content-Transfer-Encoding", transfer_encoding)
		end
		
		if (content_disposition)
			part.header.set("Content-Disposition", content_disposition)
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
		
		msg << self.content + "\r\n"
		
		self.parts.each do |part|
			msg << "--" + self.bound + "\r\n"
			msg << part.to_s
		end

		msg << "--" + self.bound + "--\r\n"
		
		msg
	end

end
end
end