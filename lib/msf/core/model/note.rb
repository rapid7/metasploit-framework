module Msf
class DBManager

class Note < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
	belongs_to :host
	belongs_to :service
	serialize :data, Msf::Util::Base64Serializer.new

	def after_save
		if data_changed? and ntype =~ /fingerprint/
			host.normalize_os
		end
	end

end

end
end

