module Msf
class DBManager

class EmailTemplate < ActiveRecord::Base
	belongs_to :campaign
	has_and_belongs_to_many :attachments
end

end
end

