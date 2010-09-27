module Msf
class DBManager

class EmailTemplate < ActiveRecord::Base
	belongs_to :campaign
	has_and_belongs_to_many :attachments

	extend SerializedPrefs

	serialize :prefs

	serialized_prefs_attr_accessor :exploit_name, :exploit_opts
	serialized_prefs_attr_accessor :generate_exe
end

end
end

