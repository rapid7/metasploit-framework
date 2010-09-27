module Msf
class DBManager

class WebTemplate < ActiveRecord::Base
	belongs_to :campaign

	extend SerializedPrefs

	serialize :prefs

	serialized_prefs_attr_accessor :exploit_type
	serialized_prefs_attr_accessor :exploit_name, :exploit_opts
end

end
end

