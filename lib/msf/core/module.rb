require 'Msf/Core'

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

	def initialize(info = {})
		self.module_info = info

		set_defaults

		# Transform some of the fields to arrays as necessary
		self.author = Rex::Transformer.transform(module_info['Author'], Array, 
				[ Author ], 'Author')
		self.arch = Rex::Transformer.transform(module_info['Arch'], Array, 
				[ String ], 'Arch')
		self.platform = Rex::Transformer.transform(module_info['Platform'], Array, 
				[ String ], 'Platform')
		self.refs = Rex::Transformer.transform(module_info['Ref'], Array,
				[ SiteReference, Reference ], 'Ref')

		# Create and initialize the option container for this module
		self.options = OptionContainer.new
		self.options.add_options(info['Options'])
		self.options.add_advanced_options(info['AdvancedOptions'])

		# Create and initialize the data store for this module
		self.datastore = DataStore.new
		self.datastore.import_options(self.options)
	end

	# Return the module's name
	def name
		return module_info['Name']
	end

	# Return the module's description
	def description
		return module_info['Description']
	end

	# Return the module's version information
	def version
		return module_info['Version']
	end

	# Return the module's abstract type
	def type
		raise NotImplementedError
	end

	# Return a comma separated list of author for this module
	def author_to_s
		return author.collect { |author| author.to_s }.join(", ")
	end

	# Enumerate each author
	def each_author(&block)
		author.each(&block)
	end

	# Return a comma separated list of supported architectures, if any
	def arch_to_s
		return arch.join(", ")
	end

	# Enumerate each architecture
	def each_arch(&block)
		arch.each(&block)
	end

	# Return whether or not the module supports the supplied architecture
	def arch?(what)
		return true if (what == ARCH_ANY)

		return arch.index(what) != nil 
	end

	# Return a comma separated list of supported platforms, if any
	def platform_to_s
		return platform.join(", ")
	end
	
	attr_reader   :author, :arch, :platform, :refs, :datastore, :options

protected

	# Sets the modules unsupplied info fields to their default values
	def set_defaults
		self.module_info = {
			'Name'        => 'No module name', 
			'Description' => 'No module description',
			'Version'     => '0',
			'Author'      => nil,
			'Arch'        => nil,
			'Platform'    => nil,
			'Ref'         => nil
		}.update(self.module_info)
	end

	#
	# Checks to see if a derived instance of a given module implements a method
	# beyond the one that is provided by a base class.  This is a pretty lame
	# way of doing it, but I couldn't find a better one, so meh.
	#
	def derived_implementor?(parent, method_name)
		(self.method(method_name).to_s.match(/#{parent.to_s}[^:]/)) ? false : true
	end

	attr_accessor :module_info
	attr_writer   :author, :arch, :platform, :refs, :datastore, :options

end

end
