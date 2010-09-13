module Msf
class DBManager

class EmailTemplate < ActiveRecord::Base
	belongs_to :campaign
	has_many :attachments
end

end
end

