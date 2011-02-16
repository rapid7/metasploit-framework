
module Msf
class Post

module Registry

	#
	# Return the data and type of a given registry key and value
	#
	def registry_getvalinfo(key,valname)
		value = {}
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value["Data"] = v.data
			value["Type"] = v.type
			open_key.close
		end
		return value
	end

	#
	# Return the data of a given registry key and value
	#
	def registry_getvaldata(key,valname)
		value = nil
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			v = open_key.query_value(valname)
			value = v.data
			open_key.close
		end
		return value
	end

	#
	# Sets the data for a given value and type of data on the target registry
	#
	# returns true if succesful
	#
	def registry_setvaldata(key,valname,data,type)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
			open_key.set_value(valname, session.sys.registry.type2str(type), data)
			open_key.close
			return true
		end
	end

	#
	# Deletes a registry value given the key and value name
	#
	# returns true if succesful
	#
	def registry_deleteval(key,valname)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_WRITE)
			open_key.delete_value(valname)
			open_key.close
			return true
		end
	end

	#
	# Return an array of value names for the given registry key
	#
	def registry_enumvals(key)
		values = []
		begin
			vals = {}
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			vals = open_key.enum_value
			vals.each { |val|
				values <<  val.name
			}
			open_key.close
		end
		return values
	end

	#
	# Return an array of subkeys for the given registry key
	#
	def registry_enumkeys(key)
		subkeys = []
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.open_key(root_key, base_key, KEY_READ)
			keys = open_key.enum_key
			keys.each { |subkey|
				subkeys << subkey
			}
			open_key.close
		end
		return subkeys
	end

	#
	# Create the given registry key
	#
	def registry_createkey(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.create_key(root_key, base_key)
			open_key.close
			return true
		end

	end

	#
	# Delete a given registry key
	#
	# returns true if succesful
	#
	def registry_delkey(key)
		begin
			root_key, base_key = session.sys.registry.splitkey(key)
			open_key = session.sys.registry.delete_key(root_key, base_key)
			open_key.close
			return true
		end

	end

end
end
end

