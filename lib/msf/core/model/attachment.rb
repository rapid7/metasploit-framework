
class Msf::DBManager

class Attachment < ActiveRecord::Base
	has_and_belongs_to_many :email_template
	belongs_to :campaign

	# Generate a unique Content-ID
	def cid
		@cid ||= Rex::Text.to_hex(name + id.to_s, '')
		@cid
	end
end

end

