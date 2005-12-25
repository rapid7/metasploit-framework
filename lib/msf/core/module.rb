require 'msf/core'

module Msf

###
#
# The module base class is responsible for providing the common interface
# that is used to interact with modules at the most basic levels, such as
# by inspecting a given module's attributes (name, dsecription, version,
# authors, etc) and by managing the module's data store.
#
###
class Module

	# Modules can subscribe to a user-interface, and as such they include the
	# UI subscriber module.  This provides methods like print, print_line, etc.
	# User interfaces are designed to be medium independent, and as such the
	# user interface subscribes are designed to provide a flexible way of
	# interacting with the user, n stuff.
	include Rex::Ui::Subscriber
	
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
		# Returns this module's ranking.
		#
		def rank
			(const_defined?('Rank')) ? const_get('Rank') : NormalRanking
		end
	
		#
		# Returns this module's ranking as a string representation.
		#
		def rank_to_s
			RankingName[rank]
		end

		# 
		# The module's name that is assigned it it by the framework
		# or derived from the path that the module is loaded from.
		#
		attr_accessor :refname

		#
		# This attribute holds the non-duplicated copy of the module
		# implementation.  This attribute is used for reloading purposes so that
		# it can be re-duplicated.
		#
		attr_accessor :orig_cls

		#
		# The path from which the module was loaded.
		#
		attr_accessor :file_path
	end

	#
	# Returns the class reference to the framework
	#
	def framework
		return self.class.framework
	end

	#
	# This method allows modules to tell the framework if they are usable
	# on the system that they are being loaded on in a generic fashion.
	# By default, all modules are indicated as being usable.  An example of
	# where this is useful is if the module depends on something external to
	# ruby, such as a binary.
	#
	def self.is_usable
		true
	end

	require 'msf/core/module/author'
	require 'msf/core/module/platform_list'
	require 'msf/core/module/reference'
	require 'msf/core/module/target'

	#
	# Creates an instance of an abstract module using the supplied information
	# hash.
	#
	def initialize(info = {})
		self.module_info = info

		set_defaults

		# Initialize module compatibility hashes
		init_compat

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
	# Returns the unduplicated class associated with this module.
	#
	def orig_cls
		return self.class.orig_cls
	end

	#
	# The path to the file in which the module can be loaded from.
	#
	def file_path
		self.class.file_path
	end

	#
	# Return the module's name from the module information hash.
	#
	def name
		module_info['Name']
	end

	#
	# Returns the module's alias, if it has one.  Otherwise, the module's
	# name is returned.
	#
	def alias
		module_info['Alias']
	end

	#
	# Return the module's description.
	#
	def description
		module_info['Description']
	end

	#
	# Return the module's version information.
	#
	def version
		module_info['Version']
	end

	#
	# Returns the hash that describes this module's compatibilities.
	#
	def compat
		module_info['Compat'] || {}
	end

	#
	# Returns whether or not this module is compatible with the supplied
	# module.
	#
	def compatible?(mod)
		ch = nil

		# Invalid module?  Shoot, we can't compare that.
		return true if (mod == nil)

		# Determine which hash to used based on the supplied module type
		if (mod.type == MODULE_ENCODER)
			ch = self.compat['Encoder']
		elsif (mod.type == MODULE_NOP)
			ch = self.compat['Nop']
		elsif (mod.type == MODULE_PAYLOAD)
			ch = self.compat['Payload']
		else
			return true
		end

		# Enumerate each compatibility item in our hash to find out
		# if we're compatible with this sucker.
		ch.each_pair { |k,v|
			
			# Get the value of the current key from the module, such as
			# the ConnectionType for a stager (ws2ord, for instance).
			mval = mod.module_info[k]

			# Skip zee nils that the module has.
			next if (mval == nil or v == nil)

			# If the supplied module's value is not contained within the supported
			# values for this module or this module indicated a negation of
			# the value stated by the supplied module, then we have detected
			# ourselves a bit of an incompatibility and we just can't have that.
			if (!(v =~ /#{mval}/) or
			    (v =~ /-#{mval}/))
				dlog("Module #{mod.refname} is incompatible with #{self.refname} for #{k}: limiter was #{v}, value was #{mval}", 
					'core', LEV_1)

				return false
			end
		}

		# If we get here, we're compatible.
		return true
	end

	#
	# Return the module's abstract type.
	#
	def type
		raise NotImplementedError
	end

	#
	# Return a comma separated list of author for this module.
	#
	def author_to_s
		return author.collect { |author| author.to_s }.join(", ")
	end

	#
	# Enumerate each author.
	#
	def each_author(&block)
		author.each(&block)
	end

	#
	# Return a comma separated list of supported architectures, if any.
	#
	def arch_to_s
		return arch.join(", ")
	end

	#
	# Enumerate each architecture.
	#
	def each_arch(&block)
		arch.each(&block)
	end

	#
	# Return whether or not the module supports the supplied architecture.
	#
	def arch?(what)
		return true if (what == ARCH_ANY)

		return arch.index(what) != nil 
	end

	#
	# Return a comma separated list of supported platforms, if any.
	#
	def platform_to_s
		return (platform.all?) ? [ "All" ] : platform.names
	end

	#
	# Returns whether or not the module requires or grants high privileges.
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

	#
	# Returns true if this module is an exploit module.
	#
	def exploit?
		return (type == MODULE_EXPLOIT)
	end

	#
	# Returns true if this module is a payload module.
	#
	def payload?
		return (type == MODULE_PAYLOAD)
	end

	#
	# Returns true if this module is an encoder module.
	#
	def encoder?
		return (type == MODULE_ENCODER)
	end

	#
	# Returns true if this module is a nop module.
	#
	def nop?
		return (type == MODULE_NOP)
	end

	#
	# Returns true if this module is a recon module.
	#
	def recon?
		return (type == MODULE_RECON)
	end

	#
	# The array of zero or more authors.
	#
	attr_reader   :author
	#
	# The array of zero or more architectures.
	#
	attr_reader   :arch
	#
	# The array of zero or more platforms.
	#
	attr_reader   :platform
	#
	# The reference count for the module.
	#
	attr_reader   :references
	#
	# The module-specific datastore instance.
	#
	attr_reader   :datastore
	#
	# The module-specific options.
	#
	attr_reader   :options
	#
	# Whether or not this module requires privileged access.
	#
	attr_reader   :privileged

protected

	#
	# The list of options that support merging in an information hash.
	#
	UpdateableOptions = [ "Name", "Description", "Alias" ]

	#
	# Sets the modules unsupplied info fields to their default values.
	#
	def set_defaults
		self.module_info = {
			'Name'        => 'No module name', 
			'Description' => 'No module description',
			'Version'     => '0',
			'Author'      => nil,
			'Arch'        => nil, # No architectures by default.
			'Platform'    => [],  # No platforms by default.
			'Ref'         => nil,
			'Privileged'  => false,
		}.update(self.module_info)
	end

	#
	# This method initializes the module's compatibility hashes by normalizing
	# them into one single hash.  As it stands, modules can define
	# compatibility in their supplied info hash through:
	#
	#   Compat        - direct compat definitions
	#   PayloadCompat - payload compatibilities
	#   EncoderCompat - encoder compatibilities
	#   NopCompat     - nop compatibilities
	#
	# In the end, the module specific compatibilities are merged as sub-hashes
	# of the primary Compat hash key to make checks more uniform.
	#
	def init_compat
		c = module_info['Compat'] = Hash.new if (module_info['Compat'] == nil)

		# Initialize the module sub compatibilities
		c['Payload'] = Hash.new if (c['Payload'] == nil)
		c['Encoder'] = Hash.new if (c['Encoder'] == nil)
		c['Nop']     = Hash.new if (c['Nop'] == nil)

		# Update the compat-derived module specific compatibilities from
		# the specific ones to make a uniform view of compatibilities
		c['Payload'].update(module_info['PayloadCompat'] || {})
		c['Encoder'].update(module_info['EncoderCompat'] || {})
		c['Nop'].update(module_info['NopCompat'] || {})
	end

	#
	# Register options with a specific owning class.
	#
	def register_options(options, owner = self.class)
		self.options.add_options(options, owner)
		self.datastore.import_options(self.options)
	end

	#
	# Register advanced options with a specific owning class.
	#
	def register_advanced_options(options, owner = self.class)
		self.options.add_advanced_options(options, owner)
		self.datastore.import_options(self.options)
	end

	#
	# Removes the supplied options from the module's option container
	# and data store.
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
	# Checks and merges the supplied key/value pair in the supplied hash.
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
					info[name] = [ curr ]
				end

				# If the value being merged is an array, add each one
				if (val.kind_of?(Array) == true)
					val.each { |v|
						if (info[name].include?(v) == false)
							info[name] << v
						end
					}
				# Otherwise just add the value
				elsif (info[name].include?(val) == false)
					info[name] << val
				end
			# Otherwise, just set the value equal if no current value
			# exists
			else
				info[name] = val
			end
		end
	end

	#
	# Merge aliases with an underscore delimiter.
	#
	def merge_info_alias(info, val)
		merge_info_string(info, 'Alias', val, '_')
	end

	#
	# Merges the module name.
	#
	def merge_info_name(info, val)
		merge_info_string(info, 'Name', val, ', ', true)
	end	

	#
	# Merges the module description.
	#
	def merge_info_description(info, val)
		merge_info_string(info, 'Description', val)
	end

	#
	# Merge the module version.
	#
	def merge_info_version(info, val)
		merge_info_string(info, 'Version', val)
	end

	#
	# Merges a given key in the info hash with a delimiter.
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
	# Merges options.
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
	# Merges advanced options.
	#
	def merge_info_advancedoptions(info, val)
		merge_info_options(info, val, true)
	end

	attr_accessor :module_info # :nodoc:
	attr_writer   :author, :arch, :platform, :references, :datastore, :options # :nodoc:
	attr_writer   :privileged # :nodoc:

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
