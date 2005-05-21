module Msf
class ModuleLoader


	attr_accessor :ext, :base, :namespace, :recursive, :history

	def initialize(namespace, base, opts = { })

		# merge in the defaults
		opts = {
		  'ext'        => '.rb',
		  'recursive'  => true
		}.update(opts)

		self.ext       = opts['ext']
		self.base      = base
		self.namespace = namespace
		self.recursive = opts['recursive']
		self.history   = { }
	end

	def mod_from_name(name)
		obj = Object

		name.split('::').each { |m|
			obj = obj.const_get(m)
		}

		return obj
	end

	def error(msg)
		puts '[!] ' + msg
	end

	def clear_history
		self.history = { }
	end

	def modload()

		loaded = { }

		mod = mod_from_name(namespace)

		# build the glob to search on
		glob = base
		glob += '/**' if(recursive)
		glob += '/*' + ext

		Dir[glob].each { |file|
			modold = mod.constants

			begin
				if !load(file)
					error('Load failed for ' + file)
					next
				end
			rescue LoadError
				error('LoadError: ' + $!)
				next
			end

			added = mod.constants - modold

			if added.length > 1
				error('More than one class added in ' + file)
				next
			end

			if added.empty?
				if history[file]
					added = history[file]
				else
					error('Loaded ' + file + ' but no class added')
					next
				end
			else
				added = mod.const_get(added[0])
			end

			loaded[file] = added
		}

		self.history.update(loaded)
		return loaded.values
	end
end end # ModuleLoader/Msf
