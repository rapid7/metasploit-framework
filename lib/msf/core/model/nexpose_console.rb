module Msf
class DBManager

class NexposeConsole < ActiveRecord::Base
	include DBSave
	serialize :cached_sites
end

end
end

