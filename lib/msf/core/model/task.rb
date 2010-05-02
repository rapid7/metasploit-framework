module Msf
class DBManager

class Task < ActiveRecord::Base
	include DBSave

	belongs_to :workspace
#
# XXX: Factor this out to extend all of ActiveRecord::Base
#
	def self.marshalize(*args)
			args.each do |method_name|
		method_declarations = %Q^
			def #{method_name}
				begin
					self[:#{method_name}] ? Marshal.load(self[:#{method_name}].unpack("m")[0]) : nil
				rescue ::Exception => e
					# Fallback to YAML to recover old data
					YAML.load(self[:#{method_name}])
				end
			end

			def #{method_name}=(value)
				self[:#{method_name}] = [Marshal.dump(value)].pack("m")
			end
^
			eval method_declarations
		end
	end

	marshalize :options
	marshalize :result
end

end
end

