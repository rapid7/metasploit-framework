
module Msf::Module::Deprecated

	# Additional class methods for deprecated modules
	module ClassMethods
		# Mark this module as deprecated
		#
		# Any time this module is run it will print warnings to that effect.
		#
		# @param deprecation_date [Date,#to_s] The date on which this module will
		#   be removed
		# @param replacement_module [String] The name of a module that users
		#   should be using instead of this deprecated one
		# @return [void]
		def deprecated(deprecation_date=nil, replacement_module=nil)
			# Yes, class instance variables.
			@replacement_module = replacement_module
			@deprecation_date = deprecation_date
		end

		# The name of a module that users should be using instead of this
		# deprecated one
		#
		# @return [String,nil]
		# @see ClassMethods#deprecated
		def replacement_module; @replacement_module; end

		# The date on which this module will be removed
		#
		# @return [Date,nil]
		# @see ClassMethods#deprecated
		def deprecation_date; @deprecation_date; end
	end

	# (see ClassMethods#replacement_module)
	def replacement_module; self.class.replacement_module; end
	# (see ClassMethods#deprecation_date)
	def deprecation_date; self.class.deprecation_date; end

	# Extends with {ClassMethods}
	def self.included(base)
		base.extend(ClassMethods)
	end

	def setup
		print_warning("*"*72)
		print_warning("*%red"+"This module is deprecated!".center(70)+"%clr*")
		if deprecation_date
			print_warning("*"+"It will be removed on or about #{deprecation_date}".center(70)+"*")
		end
		if replacement_module
			print_warning("*"+"Use #{replacement_module} instead".center(70)+"*")
		end
		print_warning("*"*72)
		super
	end

end
