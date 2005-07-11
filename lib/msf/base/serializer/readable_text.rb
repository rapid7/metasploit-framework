module Msf
module Serializer

###
#
# Text
# ----
#
# This class formats information in a plain-text format that
# is meant to be displayed on a console or some other non-GUI
# medium.
#
###
class ReadableText

	#
	# Returns a formatted string that contains information about
	# the supplied module instance.
	#
	def self.dump_module(mod, indent = "    ")
		case mod.type
			when MODULE_PAYLOAD
				return dump_payload_module(mod, indent)
			when MODULE_NOP
				return dump_basic_module(mod, indent)
			when MODULE_ENCODER
				return dump_basic_module(mod, indent)
			when MODULE_EXPLOIT
				return dump_exploit_module(mod, indent)
			else
				return dump_generic_module(mod, indent)
		end
	end

	def self.dump_exploit_module(mod, indent)
	end

	# 
	# Dumps information about a payload module.
	#
	def self.dump_payload_module(mod, indent)
		# General
		output  = "\n"
		output += "       Name: #{mod.name}\n"
		output += "    Version: #{mod.version}\n"
		output += "   Platform: #{mod.platform_to_s}\n"
		output += "       Arch: #{mod.arch.to_s}\n"
		output += "Needs Admin: " + (mod.privileged? ? "Yes" : "No") + "\n"
		output += " Total size: #{mod.size}\n"
		output += "\n"

		# Authors
		output += "Provided by:\n"
		mod.each_author { |author|
			output += indent + author.to_s + "\n"
		}
		output += "\n"

		# Options
		if (mod.options.has_options?)
			output += "Available options:\n"
			output += dump_options(mod)
			output += "\n"
		end

		# Advanced options
		if (mod.options.has_advanced_options?)
			output += "Advanced options:\n"
			output += dump_advanced_options(mod)
			output += "\n"
		end
	
		# Description
		output += "Description:\n"
		output += word_wrap(mod.description)
		output += "\n\n"
	
		return output
	end

	#
	# Dumps information about a module, just the basics.
	#
	def self.dump_basic_module(mod, indent)
		# General
		output  = "\n"
		output += "       Name: #{mod.name}\n"
		output += "    Version: #{mod.version}\n"
		output += "   Platform: #{mod.platform_to_s}\n"
		output += "       Arch: #{mod.arch.to_s}\n"
		output += "\n"

		# Authors
		output += "Provided by:\n"
		mod.each_author { |author|
			output += indent + author.to_s + "\n"
		}
		output += "\n"

		# Advanced options
		if (mod.options.has_advanced_options?)
			output += "Advanced options:\n"
			output += dump_advanced_options(mod)
			output += "\n"
		end

		# Description
		output += "Description:\n"
		output += word_wrap(mod.description)
		output += "\n\n"
	
		return output

	end

	def self.dump_generic_module(mod, indent)
	end

	#
	# Dumps the list of options associated with the
	# supplied module.
	#
	def self.dump_options(mod, indent = 4)
		tbl = Rex::Ui::Text::Table.new(
			'Indent'  => indent,
			'Columns' =>
				[
					'Name', 
					'Default',
					'Required',
					'Description'
				])

		mod.options.each_option { |name, opt|
			next if (opt.advanced?)

			val = mod.datastore[name] || opt.default || ''

			tbl << [ name, val.to_s, opt.required? ? "yes" : "no", opt.desc ]
		}

		return tbl.to_s
	end

	def self.dump_advanced_options(mod, indent = 4)
		tbl = Rex::Ui::Text::Table.new(
			'Indent'  => indent,
			'Columns' =>
				[
					'Name', 
					'Default',
					'Description'
				])

		mod.options.each_option { |name, opt|
			next if (!opt.advanced?)

			val = mod.datastore[name] || opt.default || ''

			tbl << [ name, val.to_s, word_wrap(opt.desc, 0) ]
		}

		return tbl.to_s
	end

	#
	# Jacked from Ernest Ellingson <erne [at] powernav.com>, modified
	# a bit to add indention
	#
	def self.word_wrap(str, indent = 4, col = 60)
		return Rex::Text.wordwrap(str, indent, col)
	end

end

end end
