require 'msf/core'

module Msf

###
#
# Module
# ------
#
# The module base class is responsible for providing the common interface
# that is used to interact with modules at the most basic levels, such as
# by inspecting a given module's attributes (name, dsecription, version,
# authors, etc) and by managing the module's data store.
#
###
class Module

	# Make include public so we can runtime extend
	public_class_method :include

	class <<self
		include Framework::Offspring

		#
		# Class method to figure out what type of module this is
		#
		def type
			raise NotImplementedError
		end

		def fullname
			return type + '/' + refname
		end

		# 
		# The module's name that is assigned it it by the framework
		# or derived from the path that the module is loaded from.
		#
		attr_accessor :refname
	end

	#
	# Returns the class reference to the framework
	#
	def framework
		return self.class.framework
	end

	require 'msf/core/module/author'
	require 'msf/core/module/platform_list'
	require 'msf/core/module/reference'
	require 'msf/core/module/target'

	def initialize(info = {})
		self.module_info = info

		set_defaults

		# Transform some of the fields to arrays as necessary
		self.author = Author.transform(module_info['Author'])
		self.arch = Rex::Transformer.transform(module_info['Arch'], Array, 
				[ String ], 'Arch')
		self.platform = PlatformList.transform(module_info['Platform'])
		self.references = Rex::Transformer.transform(module_info['References'], Array,
				[ SiteReference, Reference ], 'Ref')

		# Create and initialize the option container for this module
		self.options = OptionContainer.new
		self.options.add_options(info['Options'], self.class)
		self.options.add_advanced_options(info['AdvancedOptions'], self.class)

		# Create and initialize the data store for this module
		self.datastore = ModuleDataStore.new(self)
		self.datastore.import_options(self.options)

		# If there are default options, import their values into the datastore
		if (module_info['DefaultOptions'])
			self.datastore.import_options_from_hash(module_info['DefaultOptions'])
		end

		self.privileged = module_info['Privileged'] || false
	end


	#
	# Returns the module's framework full reference name.  This is the
	# short name that end-users work with (refname) plus the type
	# of module prepended.  Ex:
	#
	# payloads/windows/shell/reverse_tcp
	#
	def fullname
		return self.class.fullname
	end

	#
	# Returns the module's framework reference name.  This is the
	# short name that end-users work with.  Ex: 
	#
	# windows/shell/reverse_tcp
	#
	def refname
		return self.class.refname
	end

	#
	# Return the module's name
	#
	def name
		return module_info['Name']
	end

	#
	# Returns the module's alias, if it has one.  Otherwise, the module's
	# name is returned.
	#
	def alias
		return module_info['Alias']
	end

	#
	# Return the module's description
	#
	def description
		return module_info['Description']
	end

	#
	# Return the module's version information
	#
	def version
		return module_info['Version']
	end

	#
	# Return the module's abstract type
	#
	def type
		raise NotImplementedError
	end

	#
	# Return a comma separated list of author for this module
	#
	def author_to_s
		return author.collect { |author| author.to_s }.join(", ")
	end

	#
	# Enumerate each author
	#
	def each_author(&block)
		author.each(&block)
	end

	#
	# Return a comma separated list of supported architectures, if any
	#
	def arch_to_s
		return arch.join(", ")
	end

	#
	# Enumerate each architecture
	#
	def each_arch(&block)
		arch.each(&block)
	end

	#
	# Return whether or not the module supports the supplied architecture
	#
	def arch?(what)
		return true if (what == ARCH_ANY)

		return arch.index(what) != nil 
	end

	#
	# Return a comma separated list of supported platforms, if any
	#
	def platform_to_s
		return (platform.all?) ? [ "All" ] : platform.names
	end

	#
	# Returns whether or not the module requires or grants high privileges
	#
	def privileged?
		return (privileged == true)
	end

	#
	# The default communication subsystem for this module.  We may need to move
	# this somewhere else.
	#
	def comm
		return Rex::Socket::Comm::Local
	end

	#
	# Overrides the class' own datastore with the one supplied.  This is used
	# to allow modules to share datastores, such as a payload sharing an
	# exploit module's datastore.
	#
	def share_datastore(ds)
		self.datastore = ds
		self.datastore.import_options(self.options)
	end
	
	##
	#
	# Just some handy quick checks
	#
	##
	
	def exploit?
		return (type == MODULE_EXPLOIT)
	end

	def payload?
		return (type == MODULE_PAYLOAD)
	end

	def encoder?
		return (type == MODULE_ENCODER)
	end

	def nop?
		return (type == MODULE_NOP)
	end

	def recon?
		return (type == MODULE_RECON)
	end

	attr_reader   :author, :arch, :platform, :references, :datastore, :options
	attr_reader   :privileged

protected

	UpdateableOptions = [ "Name", "Description", "Alias" ]

	# Sets the modules unsupplied info fields to their default values
	def set_defaults
		self.module_info = {
			'Name'        => 'No module name', 
			'Description' => 'No module description',
			'Version'     => '0',
			'Author'      => nil,
			'Arch'        => nil,
			'Platform'    => '',
			'Ref'         => nil,
			'Privileged'  => false,
		}.update(self.module_info)
	end

	#
	# Register options with a specific owning class
	#
	def register_options(options, owner = self.class)
		self.options.add_options(options, owner)
		self.datastore.import_options(self.options)
	end

	#
	# Register advanced options with a specific owning class
	#
	def register_advanced_options(options, owner = self.class)
		self.options.add_advanced_options(options, owner)
		self.datastore.import_options(self.options)
	end

	#
	# Removes the supplied options from the module's option container
	# and data store
	#
	def deregister_options(*names)
		names.each { |name|
			self.options.remove_option(name)
			self.datastore.delete(name)
		}
	end

	#
	# Checks to see if a derived instance of a given module implements a method
	# beyond the one that is provided by a base class.  This is a pretty lame
	# way of doing it, but I couldn't find a better one, so meh.
	#
	def derived_implementor?(parent, method_name)
		(self.method(method_name).to_s.match(/#{parent.to_s}[^:]/)) ? false : true
	end

	#
	# Merges options in the info hash in a sane fashion, as some options
	# require special attention.
	#
	def merge_info(info, opts)
		opts.each_pair { |name, val|
			merge_check_key(info, name, val)
		}

		return info
	end

	#
	# Updates information in the supplied info hash and merges other
	# information.  This method is used to override things like Name, Version,
	# and Description without losing the ability to merge architectures,
	# platforms, and options.
	#
	def update_info(info, opts)
		opts.each_pair { |name, val|
			# If the supplied option name is one of the ones that we should
			# override by default
			if (UpdateableOptions.include?(name) == true)
				# Only if the entry is currently nil do we use our value
				if (info[name] == nil)
					info[name] = val
				end
			# Otherwise, perform the merge operation like normal
			else
				merge_check_key(info, name, val)
			end
		}

		return info
	end

	#
	# Checks and merges the supplied key/value pair in the supplied hash
	#
	def merge_check_key(info, name, val)
		if (self.respond_to?("merge_info_#{name.downcase}"))
			eval("merge_info_#{name.downcase}(info, val)")
		else
			# If the info hash already has an entry for this name
			if (info[name])
				# If it's not an array, convert it to an array and merge the
				# two
				if (info[name].kind_of?(Array) == false)
					curr       = info[name]
					info[name] = [ curr, val ] if (val != curr)
				# Otherwise, just append this item to the array entry
				else
					if (info[name].include?(val) == false)
						info[name] << val
					end
				end
			# Otherwise, just set the value equal if no current value
			# exists
			else
				info[name] = val
			end
		end
	end

	#
	# Merge aliases with an underscore delimiter
	#
	def merge_info_alias(info, val)
		merge_info_string(info, 'Alias', val, '_')
	end

	#
	# Merges the module name
	#
	def merge_info_name(info, val)
		merge_info_string(info, 'Name', val, ', ', true)
	end	

	#
	# Merges the module description
	#
	def merge_info_description(info, val)
		merge_info_string(info, 'Description', val)
	end

	#
	# Merge the module version
	#
	def merge_info_version(info, val)
		merge_info_string(info, 'Version', val)
	end

	#
	# Merges a given key in the info hash with a delimiter
	#
	def merge_info_string(info, key, val, delim = ', ', inverse = false)
		if (info[key])
			if (inverse == true)
				info[key] = info[key] + delim + val
			else
				info[key] = val + delim + info[key]
			end
		else
			info[key] = val
		end
	end

	#
	# Merges options 
	#
	def merge_info_options(info, val, advanced = false)
		key_name = ((advanced) ? 'Advanced' : '') + 'Options'

		new_cont = OptionContainer.new
		new_cont.add_options(val, advanced)
		cur_cont = OptionContainer.new
		cur_cont.add_options(info[key_name] || [], advanced)

		new_cont.each_option { |name, option|
			next if (cur_cont.get(name))

			info[key_name]  = [] if (!info[key_name])
			info[key_name] << option
		}
	end

	# 
	# Merges advanced options
	#
	def merge_info_advancedoptions(info, val)
		merge_info_options(info, val, true)
	end

	attr_accessor :module_info
	attr_writer   :author, :arch, :platform, :references, :datastore, :options
	attr_writer   :privileged

end

#
# Alias the data types so people can reference them just by Msf:: and not
# Msf::Module::
#
Author = Msf::Module::Author
Reference = Msf::Module::Reference
SiteReference = Msf::Module::SiteReference
Platform = Msf::Module::Platform
Target = Msf::Module::Target

end
