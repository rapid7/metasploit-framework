##
# This file is part of the Metasploit Framework and may be subject to
# redistribution and commercial restrictions. Please see the Metasploit
# web site for more information on licensing and terms of use.
#   http://metasploit.com/
##

require 'msf/core'
require 'rex'

class Metasploit4 < Msf::Auxiliary

	def initialize(info = {})
		super(update_info(info,
			'Name' => 'Msftidy Scan',
			'Description' => %q{
				This module scans Metasploit modules for inconsistent values in the info hash.
			},
			'Author' => [ 'mihi' ],
			'License' => MSF_LICENSE
		))
	end

	def run

		# match rules common for different module types
		name_match = RegexStringMatch.new(/^[A-Za-z0-9 !-\/:->\[\]_{}]+$/)
		version_match = RegexStringMatch.new(/^(\$Revision\$|0)$/)
		#email_match ='([0-9A-Za-z._]+( at |\[at\]| \[at\] |\[ad\]|@)[0-9A-Za-z.-]+( (\[dot\]|\{dot\}) [a-z]+)?)' # TODO
		#author_match = ArrayOrSingleMatch.new(RegexStringMatch.new(
		#	Regexp.new('^('+email_match+'|r?@?[#A-Za-z0-9 ".)\[\]=_:&,!'+"'"+'-]+|[A-Za-z0-9 "._()!-]*(<' + email_match + '>)?( *\([^()]+\))?)$')
		#))
		author_match = ArrayOrSingleMatch.new(RegexStringMatch.new(/^[^<>]*(<[^<>]*>[^<>]*)?$/)) # I give up
		arch_match = ArrayOrSingleMatch.new(ListMatch.new(ARCH_TYPES))
		platform_match = ArrayOrSingleMatch.new(ListMatch.new([
				'win',
				'linux', 'unix', 'osx',
				'bsd',
				'bsdi', 'cisco', 'irix', 'hpux',
				'solaris', 'aix', 'java', 'netware', 'php', ''
		]))
		license_match = ArrayOrSingleMatch.new(ListMatch.new([MSF_LICENSE,	BSD_LICENSE]))

		# nop rules
		nop_matchers = {
			'Name*' => name_match,
			'Description*' => RegexStringMatch.new(/./),
			'Version*' => version_match,
			'Author*' => author_match,
			'Arch*' => arch_match,
			'Platform*' => ListMatch.new(['']),
			'Ref*' => ListMatch.new([nil]),
			'Privileged*' => ListMatch.new([false]),
			'License*' => license_match,
			'Alias' => RegexStringMatch.new(/^[a-z0-9_]+$/),
			'Compat*' => HashMatch.new({
				'Payload*' => HashMatch.new({}),
				'Encoder*' => HashMatch.new({}),
				'Nop*' => HashMatch.new({})
			})
		}

		# encoder rules
		encoder_type_list = [] # filled automatically
		encoder_matchers = {
			'Name*' => name_match,
			'Description*' => RegexStringMatch.new(/./),
			'Version*' => version_match,
			'Author*' => author_match,
			'Arch*' => arch_match,
			'Platform*' => ListMatch.new(['']),
			'Ref*' => ListMatch.new([nil]),
			'Privileged*' => ListMatch.new([false]),
			'License*' => license_match,
			'EncoderType' => CollectMatch.new(encoder_type_list, /^[a-z0-9_]+$/),
			'Decoder' => HashMatch.new({
				'BlockSize*' => ListMatch.new([1,4,8]),
				'KeyOffset' => ListMatch.new([2]),
				'KeySize' => ListMatch.new([4,8]),
				'KeyPack' => ListMatch.new(['V', 'N', 'Q']),
				'Stub' => RegexStringMatch.new(/./)
			}),
			'Compat*' => HashMatch.new({
				'Payload*' => HashMatch.new({}),
				'Encoder*' => HashMatch.new({}),
				'Nop*' => HashMatch.new({})
			})
		}

		# auxiliary rules
		auxiliary_matchers = {
			'Name*' => name_match,
			'Description*' => RegexStringMatch.new(/./),
			'Version*' => version_match,
			'Author*' => author_match,
			'Arch*' => ListMatch.new([nil]),
			'Platform*' => ListMatch.new([[]]),
			'Ref*' => ListMatch.new([nil]),
			'Privileged*' => ListMatch.new([false]),
			'License*' => license_match,
			'References' => ReferencesMatch.new(),
			'DefaultOptions' => HashMatch.new({
				'DCERPC::fake_bind_multi' => ListMatch.new([false]),
				'DCERPC::ReadTimeout' => ListMatch.new([300]),
				'InitialAutoRunScript' => ListMatch.new(['migrate -f']),
				'HTTP::server_name' => ListMatch.new(['IIS']),
				'SRVPORT' => ListMatch.new([80])
			}),
			'Stance' => ListMatch.new(['passive']),
			'Compat*' => HashMatch.new({
				'Payload*' => HashMatch.new({}),
				'Encoder*' => HashMatch.new({}),
				'Nop*' => HashMatch.new({})
			}),
			'DisclosureDate' => DisclosureDateMatch.new(),
			'Actions' => TODOMatch.new(), #  ['Name1', 'Name2'] or [['Name1', {Args1}], ['Name2', {Args2}], ['Name3', {Args3}]]
			'PassiveActions' => TODOMatch.new(), # like Actions
			'DefaultAction' => RegexStringMatch.new(/[A-Za-z0-9 ]+/), # TODO one of Actions
			'Passive' => ListMatch.new([true]),
			'DefaultTarget' => OrMatch.new(ListMatch.new([0]), RegexStringMatch.new(/[A-Za-z0-9 ]+/)), # TODO one of Targets
			'Targets' => TODOMatch.new()
		}

		# payload rules
		payload_connection_type_list = []
		payload_convention_list = []
		payload_required_cmd = []
		payload_matchers = {
			'Name*' => CommaListMatch.new(name_match),
			'Description*' => RegexStringMatch.new(/./),
			'Version*' => CommaListMatch.new(version_match),
			'Author*' => author_match,
			'Arch*' => arch_match,
			'Platform*' => platform_match,
			'Ref*' => ListMatch.new([nil]),
			'Privileged*' => ListMatch.new([false, true]),
			'License*' => license_match,
			'Handler' => TODOMatch.new(), # KindMatch.new(Module),
			'Session' => KindMatch.new(Class),
			'Payload' => TODOMatch.new(),
			'Compat*' => HashMatch.new({
				'Payload*' => HashMatch.new({
					'Convention' => RegexStringMatch.new(/[a-z +-]+/), # TODO
				}),
				'Encoder*' => HashMatch.new({}),
				'Nop*' => HashMatch.new({})
			}),
			'ConnectionType*' => CollectMatch.new(encoder_type_list, /^[a-z0-9_]+$/),
			'PayloadCompat' => HashMatch.new({
				'Convention*' => CollectMatch.new(payload_convention_list, /[a-z]+/), # TODO both?
			}),
			'PayloadType' => ListMatch.new(['cmd', 'cmd_interact', 'cmd_bash']),
			'RequiredCmd' => CollectMatch.new(payload_required_cmd, /[a-z-]+/),
			'References' => ReferencesMatch.new(),
			'Stage' => HashMatch.new({
				'Offsets' => TODOMatch.new(),
				'Payload' => RegexStringMatch.new(//),
				'Assembly' => RegexStringMatch.new(//)
			}),
			'Convention' => CollectMatch.new(payload_convention_list, /[a-z]+/), # TODO both?
			'Stager' => HashMatch.new({
				'RequiresMidstager' => ListMatch.new([false]),
				'Offsets' => TODOMatch.new(),
				'Payload' => RegexStringMatch.new(//),
				'Assembly' => RegexStringMatch.new(//)
			}),
			'SymbolLookup' => ListMatch.new(['ws2ord'])
		}

		# post module rules
		post_matchers = {
			'Name*' => name_match,
			'Description*' => RegexStringMatch.new(/./),
			'Version*' => version_match,
			'Author*' => author_match,
			'Arch*' => ListMatch.new([nil]),
			'Platform*' => platform_match,
			'Ref*' => ListMatch.new([nil]),
			'Privileged*' => ListMatch.new([false]),
			'License*' => license_match,
			'SessionTypes*' => ArrayOrSingleMatch.new(ListMatch.new(['shell', 'meterpreter'])),
			'Compat*' => HashMatch.new({
				'Payload*' => HashMatch.new({}),
				'Encoder*' => HashMatch.new({}),
				'Nop*' => HashMatch.new({})
			}),
			'References' => ReferencesMatch.new(),
			'Actions' => TODOMatch.new(),
			'DefaultAction' => RegexStringMatch.new(/[A-Za-z0-9 ]+/), # TODO one of Actions
			'DisclosureDate' => DisclosureDateMatch.new()
		}

		# exploit rules
		exploit_matchers = {
			'Name*' => name_match,
			'Description*' => RegexStringMatch.new(/./),
			'Version*' => version_match,
			'Author*' => author_match,
			'Arch*' => OrMatch.new(arch_match, ListMatch.new([nil])),
			'Platform*' => platform_match,
			'Ref*' => ListMatch.new([nil]),
			'Privileged*' => ListMatch.new([false, true]),
			'License*' => license_match,
			'References' => ReferencesMatch.new(),
			'DefaultOptions' => TODOMatch.new(),
			'Payload' => TODOMatch.new(),
			'Targets' => TODOMatch.new(),
			'DisclosureDate' => DisclosureDateMatch.new(),
			'DefaultTarget' => TODOMatch.new(), # TODO one of Targets
			'Compat*' => HashMatch.new({
				'PayloadType' => ListMatch.new(['cmd']), #TODO?
				'Payload*' => TODOMatch.new(),
				'Encoder*' => HashMatch.new({}),
				'Nop*' => HashMatch.new({}),
				'RequiredCmd' => TODOMatch.new(), #TODO payload_required_cmd
			}),
			'SaveRegisters' => TODOMatch.new(),
			'Stance' => ArrayOrSingleMatch.new(ListMatch.new(['aggressive', 'passive'])),
			'SessionTypes' => ArrayOrSingleMatch.new(ListMatch.new(['shell', 'meterpreter'])),
		}

		# exploit autopwn rules (TODO get them)
		exploit_autopwn_matchers = {
			'ua_name' => ListMatch.new(['Firefox', 'Opera', 'MSIE', 'Safari']),
			'ua_minver' => RegexStringMatch.new(/[0-9.]+/),
			'ua_maxver' => RegexStringMatch.new(/[0-9.]+/),
			#'ua_ver' => ListMatch.new([]),
			'classid' => ArrayOrSingleMatch.new(RegexStringMatch.new(//)),
			'method' => ArrayOrSingleMatch.new(RegexStringMatch.new(//)),
			'javascript' => ListMatch.new([true, false]),
			'os_name' => ArrayOrSingleMatch.new(ListMatch.new(['Microsoft Windows', 'Linux', 'Mac OS X'])),
			#'os_ver' => ListMatch.new([]),
			#'postfix_html' => ListMatch.new([]),
			#'prefix_html' => ListMatch.new([]),
			'vuln_test' => RegexStringMatch.new(//),
			'rank' => NumberMatch.new(300,600)
		}

		# now do all the checks
		module_checks = [
			['nops', framework.modules.nops, nop_matchers],
			['encoders', framework.modules.encoders, encoder_matchers],
			['auxiliary', framework.modules.auxiliary, auxiliary_matchers],
			['payloads', framework.modules.payloads, payload_matchers],
			['post', framework.modules.post, post_matchers],
			['exploits', framework.modules.exploits, exploit_matchers],
			['autopwn exploits', framework.modules.exploits, exploit_autopwn_matchers, :autopwn_opts],
		]
		module_checks.each do |module_check|
			type,module_hash,raw_matchers,accessor = module_check
			matchers={}
			required_keys=[]
			raw_matchers.each_pair do |origkey,value|
				key=origkey.dup
				if /\*$/.match(key)
					key[-1,1] = ''
					required_keys.push key
				end
				matchers[key] = value
			end
			module_hash.each_key do |name|
				missing_required_keys = required_keys.dup
				if accessor.nil?
					minfo = module_hash.create(name).send(:module_info)
				else
					minfo = {}
					mod = module_hash.create(name).class
					if mod.respond_to?(accessor)
						mod.send(accessor).each_pair do |key,value|
							if not value.nil?
								minfo[key.to_s] = value
							end
						end
					end
				end
				matchers.each_value do |matcher|
					matcher.reset()
				end
				minfo.each_pair do |key,value|
					missing_required_keys.delete key
					matcher = matchers[key]
					if matcher.nil? or not matcher.match?(value) then
						print_status "#{type}/#{name}: #{key} = #{value}"
					end
				end
				matchers.each_pair do |key,matcher|
					if not matcher.validate()
						print_status "#{type}/#{name}: #{key} inconsistent"
					end
				end
				missing_required_keys.each do |key|
					print_status "#{type} #{name}: missing #{key}"
				end
			end
		end
	end

	class Match

		def reset()
		end

		def match?(value)
			true
		end

		def validate()
			true
		end
	end

	class ListMatch < Match
		def initialize(list)
			@list = list
		end

		def match?(value)
			@list.include?(value)
		end
	end

	class RegexStringMatch < Match
		def initialize(regex)
			@regex = regex
		end

		def match?(value)
			value.kind_of? String and @regex.match(value)
		end
	end

	class NumberMatch < Match
		def initialize(from, to)
			@from = from
			@to = to
		end

		def match?(value)
			value.kind_of? Fixnum and value >= @from and value <= @to
		end
	end

	class KindMatch < Match
		def initialize(type)
			@type = type
		end

		def match?(value)
			value.kind_of? @type
		end
	end

	class ArrayOrSingleMatch < Match
		def initialize(match)
			@match = match
		end

		def reset()
			@match.reset
		end

		def match?(value)
			if value.kind_of? Array
				value.each do |elem|
					if not @match.match?(elem)
						return false
					end
				end
				return true
			end
			@match.match?(value)
		end

		def validate
			@match.validate
		end
	end

	class CommaListMatch < ArrayOrSingleMatch
		def match?(value)
			''.empty? or super(value.split(', '))
		end
	end

	class HashMatch < Match
		def initialize(opts)
			@matchers = {}
			@required = []
			opts.each_pair do |origkey,value|
				key=origkey.dup
				if /\*$/.match(key)
					key[-1,1] = ''
					@required.push key
				end
				@matchers[key] = value
			end
		end

		def reset()
			@matchers.each_value do |value|
				value.reset()
			end
		end

		def match?(value)
			if not value.kind_of? Hash
				return false
			end
			missing_required = @required.dup
			value.each_pair do |key,value|
				missing_required.delete key
				matcher = @matchers[key]
				if matcher.nil? or not matcher.match?(value)
					return false
				end
			end
			return missing_required.empty?
		end

		def validate()
			@matchers.each_value do |value|
				if not value.validate()
					return false
				end
			end
			return true
		end
	end

	class OrMatch < Match
		def initialize(*matches)
			@matches = matches
		end

		def reset()
			@matches.each do |match|
				match.reset
			end
		end

		def match?(value)
			@matches.each do |match|
				if match.match?(value)
					return true
				end
			end
			return false
		end

		def validate
			@matches.each do |match|
				if match.validate()
					return true
				end
			end
			return false
		end
	end

	class CollectMatch < Match
		def initialize(list, regex)
			@list = list
			@regex = regex
		end

		def match?(value)
			if not value.kind_of? String or not @regex.match(value)
				return false
			end
			if not @list.include?(value)
				@list.push value
			end
			true
		end
	end

	class ReferencesMatch < Match

		def initialize()
			@allowed_refs = {
				'CVE' => /^[0-9]{4}-[0-9]{4}$/,
				'WVE' => /^[0-9]{4}-[0-9]{4}$/,
				'BID' => /^[1-9][0-9]*$/,
				'OSVDB' => /^[1-9][0-9]*$/,
				'EDB' => /^[1-9][0-9]*$/,
				'UDB' => /^[1-9][0-9]*$/,
				'SECUNIA' => /^[1-9][0-9]*$/,
				'MSB' => /^MS[0-9]{2}-[0-9]{3}$/,
				'US-CERT-VU' => /^[1-9][0-9]*$/,
				'MIL' => /^(68|9663)$/, # TODO
				'MSF' => /[a-z0-9\/_]+/,
				'URL' => /^(https?:\/\/|ftp:\/\/|www\.)[^ <>"]*$/
			}
		end

		def match?(value)
			if not value.kind_of? Array
				return false
			end
			value.each do |arr|
				if not arr.kind_of? Array or arr.length != 2
					return false
				end
				type, ref = arr
				refregex = @allowed_refs[type]
				if refregex.nil? or not ref.kind_of? String or not refregex.match(ref)
					return false
				end
			end
		end
	end

	class DisclosureDateMatch < Match
		def match?(value)
			if not value.kind_of? String or not /^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-3]?[0-9] [12][0-9]{3}$/.match(value)
				return false
			end
			begin
				d = Date.strptime(value, '%b %d %Y')
				return (d >= Date.new(1993,11,14) and d < DateTime.now)
			rescue ArgumentError
				return false
			end
		end
	end

	class TODOMatch < Match
		#TODO remove
	end
end
