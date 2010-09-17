
class Msf::DBManager

class Attachment < ActiveRecord::Base
	has_and_belongs_to_many :email_template
end

end

