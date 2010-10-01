module Msf
class DBManager

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

	serialized_prefs_attr_accessor :do_web
	serialized_prefs_attr_accessor :do_email

end

end
end

