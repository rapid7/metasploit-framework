module Msf
class DBManager

module SerializedPrefs
	def serialized_prefs_attr_accessor(*args)
		args.each do |method_name|
			method_declarations = %Q^
				def #{method_name}
					return if not self.prefs
					self.prefs[:#{method_name}]
				end

				def #{method_name}=(value)
					temp = self.prefs || {}
					temp[:#{method_name}] = value
					self.prefs = temp
				end
^
			class_eval method_declarations
		end
	end

end


class Campaign < ActiveRecord::Base
	has_one :email_template
	has_one :web_template
	has_many :email_addresses

	extend SerializedPrefs

	serialize :prefs

	# Email settings
	serialized_prefs_attr_accessor :smtp_server, :smtp_port, :smtp_ssl
	serialized_prefs_attr_accessor :smtp_user, :smtp_pass
	serialized_prefs_attr_accessor :mailfrom

	# Web settings
	serialized_prefs_attr_accessor :web_uripath, :web_srvport, :web_srvhost
	serialized_prefs_attr_accessor :web_ssl

end

end
end

