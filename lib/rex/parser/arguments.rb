module Rex
module Parser

###
#
# Arguments
# ---------
#
# This class parses arguments in a getopt style format, kind of.
# Unfortunately, the default ruby getopt implementation will only
# work on ARGV, so we can't use it.
#
###
class Arguments

	#
	# Specifies that an option is expected to have an argument
	#
	HasArgument = (1 << 0)

	#
	# Initializes the format list with an array of formats like:
	#
	# Arguments.new(
	#    '-b' => [ false, "some text" ]
	# )
	#
	def initialize(fmt)
		self.fmt = fmt
	end

	#
	# Parses the supplied arguments into a set of options
	#
	def parse(args, &block)
		args.each_with_index { |arg, idx|
			if (arg.match(/^-/))
				cfs = arg[0..2]

				fmt.each_pair { |fmtspec, val|
					next if (fmtspec != cfs)

					param = nil

					if (val[0])
						param = args[idx+1]
					end

					yield fmtspec, idx, param
				}
			else
				yield nil, idx, arg
			end
		}
	end

	#
	# Returns usage information for this parsing context
	#
	def usage
		txt = "\nOPTIONS:\n\n"

		fmt.each_pair { |fmtspec, val|
			txt += "    #{fmtspec}" + ((val[0] == true) ? " <opt>  " : "        ")
			txt += val[1] + "\n"
		}

		txt += "\n"

		return txt
	end

	attr_accessor :fmt

end

end
end
