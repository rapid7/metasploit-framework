#    This file is part of Metasm, the Ruby assembly manipulation suite
#    Copyright (C) 2007 Yoann GUILLOT
#
#    Licence is LGPL, see LICENCE in the top-level directory


require 'metasm/main'
require 'metasm/encode'
require 'metasm/preprocessor'

module Metasm
class Data
	# keywords for data definition (used to recognize label names)
	DataSpec = %w[db dw dd dq]
end

class CPU
	# parses prefix/name/arguments
	# returns an +Instruction+ or raise a ParseError
	def parse_instruction(lexer)
		i = Instruction.new self

		# find prefixes, break on opcode name
		while tok = lexer.readtok and parse_prefix(i, tok.raw)
			lexer.skip_space_eol
		end
	
		# allow '.' in opcode name
		tok = tok.dup
		while ntok = lexer.nexttok and ntok.type == :punct and ntok.raw == '.'
			tok.raw << lexer.readtok.raw
			ntok = lexer.readtok
			raise tok, 'invalid opcode name' if not ntok or ntok.type != :string
			tok.raw << ntok.raw
		end

		raise tok, 'invalid opcode' if not opcode_list_byname[tok.raw]

		i.opname = tok.raw
		i.backtrace = tok.backtrace.dup
		lexer.skip_space

		# find arguments list
		loop do
			if not ntok = lexer.nexttok or opcode_list_byname[ntok.raw] or not arg = parse_argument(lexer)
				break if i.args.empty?
				raise tok, 'invalid argument'
			end
			i.args << arg
			lexer.skip_space
			break if not ntok = lexer.nexttok or ntok.type != :punct or ntok.raw != ','
			lexer.readtok
			lexer.skip_space_eol
		end

		opcode_list_byname[i.opname].to_a.find { |o|
			o.args.length == i.args.length and o.args.zip(i.args).all? { |f, a| parse_arg_valid?(o, f, a) }
		} or raise tok, "invalid opcode arguments #{i.to_s.inspect}"

		parse_instruction_fixup(i)

		i
	end

	# called after the instruction is fully parsed
	def parse_instruction_fixup(i)
	end

	# return false if not a prefix
	def parse_prefix(i, word)
	end

	# returns a parsed argument
	# add your own arguments parser here (registers, memory references..)
	def parse_argument(lexer)
		Expression.parse(lexer)
	end

	# handles .instructions
	# XXX handle HLA here ?
	def parse_parser_instruction(lexer, instr)
		raise instr, 'unknown parser instruction'
	end
end

# asm-specific preprocessor
# handles asm arguments (; ... eol)
# asm macros (name macro args\nbody endm, name equ val)
# initializes token.value (reads integers in hex etc)
# merges consecutive space/eol
class AsmPreprocessor
	# an assembler macro, similar to preprocessor macro
	# handles local labels
	class Macro
		attr_accessor :name, :args, :body, :labels
		
		def initialize(name)
			@name = name
			@args, @body, @labels = [], [], []
		end

		# returns the array of token resulting from the application of the macro
		# parses arguments if needed, handles macro-local labels
		def apply(macro, lexer, program)
			# read arguments
			args = []
			lexer.skip_space
			if not @args.empty? and tok = lexer.nexttok and tok.type == :punct and tok.raw == '('
				lexer.readtok
				loop do
					lexer.skip_space_eol
					args << Expression.parse_toks(lexer)
					lexer.skip_space_eol
					raise @name, 'invalid arg list' if not tok = lexer.readtok or tok.type != :punct or (tok.raw != ')' and tok.raw != ',')
					break if tok.raw == ')'
				end
			end
			raise @name, 'invalid argument count' if args.length != @args.length

			labels = @labels.inject({}) { |h, l| h.update l => program.new_label(l) }
			args = @args.zip(args).inject({}) { |h, (fa, a)| h.update fa.raw => a }

			# apply macro
			@body.map { |t|
				t = t.dup
				t.backtrace += macro.backtrace[-2..-1] if not macro.backtrace.empty?
				if labels[t.raw]
					t.raw = labels[t.raw]
				elsif args[t.raw]
					args[t.raw].map { |a|
						tt = a.dup
						tt.backtrace = t.backtrace
						tt
					}
				else
					t
				end
			}.flatten
		end

		# parses the argument list and the body from lexer
		# recognize the local labels
		# XXX add eax,
		#      toto db 42	; zomg h4x
		def parse_definition(lexer)
			lexer.skip_space
			while tok = lexer.nexttok and tok.type != :eol
				# no preprocess argument list
				raise @name, 'invalid arg definition' if not tok = lexer.readtok or tok.type != :string
				@args << tok
				lexer.skip_space
				raise @name, 'invalid arg separator' if not tok = lexer.readtok or ((tok.type != :punct or tok.raw != ',') and tok.type != :eol)
				break if tok.type == :eol
				lexer.skip_space
			end

			lexer.skip_space_eol
			while tok = lexer.readtok and (tok.type != :string or tok.raw != 'endm')
				@body << tok
				if @body[-2] and @body[-2].type == :string and @body[-1].raw == ':' and (not @body[-3] or @body[-3].type == :eol)
					@labels[@body[-2].raw] = true
				elsif @body[-3] and @body[-3].type == :string and @body[-2].type == :space and Data::DataSpec.include?(@body[-1].raw) and (not @body[-4] or @body[-4].type == :eol)
					@labels[@body[-3].raw] = true
				end
			end
		end
	end

	# the program (used to create new label names)
	attr_accessor :program
	# hash macro name => Macro
	attr_accessor :macro

	def initialize(program)
		@program = program
		@macro = {}
		super()
	end

	def skip_space_eol
		readtok while t = nexttok and (t.type == :space or t.type == :eol)
	end

	def skip_space
		readtok while t = nexttok and t.type == :space
	end

	def nexttok
		t = readtok
		unreadtok t
		t
	end

	# reads a token, handles macros/comments/integers/etc
	# argument is for internal use
	def readtok_asmpp(rec = false)
		tok = readtok_cpp

		# handle ; comments
		if tok and tok.type == :punct and tok.raw == ';'
			tok.type = :eol
			begin
				tok = tok.dup
				while ntok = readtok_cpp and ntok.type != :eol
					tok.raw << ntok.raw
				end
				tok.raw << ntok.raw if ntok
			rescue ParseError
				# unterminated string
			end
		end

		# aggregate space/eol
		if tok and (tok.type == :space or tok.type == :eol)
			if ntok = readtok and ntok.type == :space
				tok = tok.dup
				tok.raw << ntok.raw
			elsif ntok and ntok.type == :eol
				tok = tok.dup
				tok.raw << ntok.raw
				tok.type = :eol
			else
				unreadtok ntok
			end
		end


		# handle macros
		# the rec parameter is used to avoid reading the whole text at once when reading ahead to check 'macro' keyword
		if not rec and tok and tok.type == :string
			if @macro[tok.raw]
				@macro[tok.raw].apply(tok, self, @program).reverse_each { |t| unreadtok t }
				tok = readtok

			else
				if ntok = readtok(true) and ntok.type == :space and nntok = readtok(true) and nntok.type == :string and (nntok.raw == 'macro' or nntok.raw == 'equ')
					puts "W: asm: redefinition of macro #{tok.raw} at #{tok.backtrace_str}, previous definition at #{@macro[tok.raw].name.backtrace_str}" if @macro[tok.raw]
					m = Macro.new tok
					# XXX this allows nested macro definition..
					if nntok.raw == 'macro'
						m.parse_definition self
					else
						m.body = Expression.parse_toks(self)
					end
					@macro[tok.raw] = m
					tok = readtok
				else
					unreadtok nntok
					unreadtok ntok
				end
			end
		end

		tok
	end
	alias readtok readtok_asmpp
end

class ExeFormat
	# setup self.cursource here
	def parse_init
	end

	# parses an asm source file to an array of Instruction/Data/Align/Offset/Padding
	def parse(text, file='<ruby>', lineno=0)
		parse_init
		@lexer ||= AsmPreprocessor.new(self)
		@lexer.feed text, file, lineno
		lasteol = true

		while not @lexer.eos?
			tok = @lexer.readtok
			next if not tok
			case tok.type
			when :space
			when :eol
				lasteol = true
			when :punct
				case tok.raw
				when '.'
					tok = tok.dup
					while ntok = @lexer.nexttok and ((ntok.type == :string) or (ntok.type == :punct and ntok.raw == '.'))
						tok.raw << @lexer.readtok.raw
					end
					parse_parser_instruction tok
				else raise tok, 'syntax error'
				end
				lasteol = false
			when :string
				ntok = nntok = nil
				if lasteol and ((ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ':') or (nntok = @lexer.nexttok and ntok.type == :space and nntok.type == :string and Data::DataSpec.include?(nntok.raw)))
					l = Label.new(tok.raw)
					l.backtrace = tok.backtrace.dup
					@knownlabel ||= {}
					raise tok, "label redefinition, previous definition at #{@knownlabel[tok.raw].backtrace_str}" if @knownlabel[tok.raw]
					@knownlabel[tok.raw] = l
					@cursource << l
					lasteol = false
					next
				end
				lasteol = false
				@lexer.unreadtok ntok
				@lexer.unreadtok tok
				if Data::DataSpec.include?(tok.raw)
					@cursource << parse_data
				else
					@cursource << @cpu.parse_instruction(@lexer)
				end
			else
				raise tok, 'syntax error'
			end
		end
	end

	# handles special directives (alignment, changing section, ...)
	# special directives start with a dot
	def parse_parser_instruction(tok)
		case tok.raw.downcase
		when '.align'
			e = Expression.parse(@lexer).reduce
			raise self, 'need immediate alignment size' unless e.kind_of? Integer
			@lexer.skip_space
			if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
				@lexer.skip_space_eol
				# allow single byte value or full data statement
				if not ntok = @lexer.readtok or not ntok.type == :string or not Data::DataSpec.include?(ntok.raw)
					@lexer.unreadtok ntok
					type = 'db'
				else
					type = ntok.raw
				end
				fillwith = parse_data_data type
			else
				@lexer.unreadtok ntok
			end
			raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
			@cursource << Align.new(e, fillwith, tok.backtrace.dup)

		when '.pad'
			@lexer.skip_space
			if ntok = @lexer.readtok and ntok.type != :eol
				# allow single byte value or full data statement
				if not ntok.type == :string or not Data::DataSpec.include?(ntok.raw)
					@lexer.unreadtok ntok
					type = 'db'
				else
					type = ntok.raw
				end
				fillwith = parse_data_data(type)
			else
				@lexer.unreadtok ntok
			end
			raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
			@cursource << Padding.new(fillwith, tok.backtrace.dup)

		when '.offset'
			e = Expression.parse(@lexer).reduce
			raise tok, 'need immediate offset value' unless e.kind_of? Integer
			raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
			@cursource << Offset.new(e, tok.backtrace.dup)

		when '.padto'
			e = Expression.parse(@lexer).reduce
			raise self, 'need immediate alignment size' unless e.kind_of? Integer
			@lexer.skip_space
			if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
				@lexer.skip_space
				# allow single byte value or full data statement
				if not ntok = @lexer.readtok or not ntok.type == :string or not Data::DataSpec.include?(ntok.raw)
					@lexer.unreadtok ntok
					type = 'db'
				else
					type = ntok.raw
				end
				fillwith = parse_data_data type
			else
				@lexer.unreadtok ntok
			end
			raise tok, 'syntax error' if ntok = @lexer.nexttok and ntok.type != :eol
			@cursource << Padding.new(fillwith, tok.backtrace.dup) << Offset.new(e, tok.backtrace.dup)

		else
			@cpu.parse_parser_instruction(self, tok)
		end
	end

	def parse_data
		raise ParseError, 'internal error' if not tok = @lexer.readtok
		raise tok, 'invalid data type' if tok.type != :string or not Data::DataSpec.include?(tok.raw)
		type = tok.raw
		@lexer.skip_space_eol
		arr = []
		loop do
			arr << parse_data_data(type)
			@lexer.skip_space
			if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
				@lexer.skip_space_eol
			else
				@lexer.unreadtok ntok
				break
			end
		end
		Data.new(type, arr, 1, tok.backtrace.dup)
	end

	def parse_data_data(type)
		raise ParseError, 'need data content' if not tok = @lexer.readtok
		if tok.type == :punct and tok.raw == '?'
			Data.new type, :uninitialized, 1, tok.backtrace.dup
		elsif tok.type == :quoted
			Data.new type, tok.value, 1, tok.backtrace.dup
		else
			@lexer.unreadtok tok
			raise tok, 'invalid data' if not i = Expression.parse(@lexer)
			@lexer.skip_space
			if ntok = @lexer.readtok and ntok.type == :string and ntok.raw.downcase == 'dup'
				raise ntok, 'need immediate count expression' unless (count = i.reduce).kind_of? Integer
				raise ntok, 'syntax error, ( expected' if not ntok = @lexer.readtok or ntok.type != :punct or ntok.raw != '('
				content = []
				loop do
					content << parse_data_data(type)
					@lexer.skip_space
					if ntok = @lexer.readtok and ntok.type == :punct and ntok.raw == ','
						@lexer.skip_space_eol
					else
						@lexer.unreadtok ntok
						break
					end
				end
				raise ntok, 'syntax error, ) expected' if not ntok = @lexer.readtok or ntok.type != :punct or ntok.raw != ')'
				Data.new type, content, count, tok.backtrace.dup
			else
				@lexer.unreadtok ntok
				Data.new type, i, 1, tok.backtrace.dup
			end
		end
	end
end

class Expression
	class << self
		# key = operator, value = hash regrouping operators of lower precedence
		OP_PRIO = [[:'||'], [:'&&'], [:|], [:^], [:&], [:'==', :'!='],
			[:'<', :'>', :'<=', :'>='], [:<<, :>>], [:+, :-], [:*, :/, :%]
		].inject({}) { |h, oplist|
			lessprio = h.keys.inject({}) { |hh, op| hh.update op => true }
			oplist.each { |op| h[op] = lessprio }
			h }


		# reads an operator from the lexer, returns the corresponding symbol or nil
		def readop(lexer)
			if not tok = lexer.readtok or tok.type != :punct
				lexer.unreadtok tok
				return
			end

			if tok.value
				if OP_PRIO[tok.value]
					return tok
				else
					lexer.unreadtok tok
					return
				end
			end

			op = tok
			case op.raw
			# may be followed by itself or '='
			when '>', '<'
				if ntok = lexer.readtok and ntok.type == :punct and (ntok.raw == op.raw or ntok.raw == '=')
					op = op.dup
					op.raw << ntok.raw
				else
					lexer.unreadtok ntok
				end
			# may be followed by itself
			when '|', '&'
				if ntok = lexer.readtok and ntok.type == :punct and ntok.raw == op.raw
					op = op.dup
					op.raw << ntok.raw
				else
					lexer.unreadtok ntok
				end
			# must be followed by '='
			when '!', '='
				if not ntok = lexer.readtok or ntok.type != :punct and ntok.raw != '='
					lexer.unreadtok ntok
					lexer.unreadtok tok
					return
				end
				op = op.dup
				op.raw << ntok.raw
			# ok
			when '^', '+', '-', '*', '/', '%'
			# unknown
			else
				lexer.unreadtok tok
				return
			end
			op.value = op.raw.to_sym
			op
		end

		# parses an integer/a float, sets its tok.value, consumes&aggregate necessary following tokens (point, mantissa..)
		# handles $/$$ special asm label name
		def parse_intfloat(lexer, tok)
			if not tok.value and tok.raw =~ /^[a-f][0-9a-f]*h$/i
				puts "W: Parser: you may want to add a leading 0 to #{tok.raw.inspect} at #{tok.backtrace[-2]}:#{tok.backtrace[-1]}"
			end
			if tok.raw == '$' and lexer.program
				if not (l = lexer.program.cursource.last).kind_of? Label
					l = Label.new(lexer.program.new_label('instr_start'))
					l.backtrace = tok.backtrace.dup
					lexer.program.cursource << l
				end
				tok.value = l.name
				return
			elsif tok.raw == '$$' and lexer.program
				if not (l = lexer.program.cursource.first).kind_of? Label
					l = Label.new(lexer.program.new_label('section_start'))
					l.backtrace = tok.backtrace.dup
					lexer.program.cursource.unshift l
				end
				tok.value = l.name
				return
			end

			if not tok.value and tok.type == :punct and tok.raw == '.'
				# bouh
				ntok = lexer.readtok
				lexer.unreadtok ntok
				if ntok and ntok.type == :string and ntok.raw =~ /^[0-9][0-9e_]*$/ and ntok.raw.count('e') <= 1
					point = tok.dup
					lexer.unreadtok point
					tok.raw = '0'
					tok.type = :string
				end
			end

			return if tok.value or not (?0..?9).include? tok.raw[0]

			case tok.raw
			when /^0b([01_]+)$/, /^([01_]+)b$/
				tok.value = $1.to_i(2)
			when /^(0[0-7_]+)$/
				tok.value = $1.to_i(8)
			when /^0x([a-fA-F0-9_]+)$/, /^([0-9][a-fA-F0-9_]*)h$/
				tok.value = $1.to_i(16)
			when /^[0-9_]+l?$/i
				# TODO 1e3 == 1000
				if ntok = lexer.readtok and ntok.type == :punct and ntok.raw == '.'
					# parse float
					tok.raw << ntok.raw
					ntok = lexer.readtok
					# XXX 1.0e2 => '1', '.', '0e2'
					raise tok, 'invalid float'+ntok.raw.inspect if not ntok or ntok.type != :string or ntok.raw !~ /^[0-9][0-9_e]*$/ or ntok.raw.count('e') > 1
					if ntok.raw.include? 'e'
						ntok.raw, post = ntok.raw.split('e', 2)
						if post.length > 0
							t = ntok.dup
							t.raw = post
							lexer.unreadtok t
						end
						t = ntok.dup
						t.raw = 'e'
						lexer.unreadtok t
					end
					tok.raw << ntok.raw

					if ntok = lexer.readtok and ntok.type == :string and ntok.raw == 'e'
						tok.raw << ntok.raw
						ntok = lexer.readtok
						if ntok and ntok.type == :punct and (ntok.raw == '-' or ntok.raw == '+')
							tok.raw << ntok.raw
							ntok = lexer.readtok
						end
						raise tok, 'invalid float' if not ntok or ntok.type != :string or ntok.raw !~ /^[0-9_]+$/
						tok.raw << ntok.raw
					else
						lexer.unreadtok ntok
					end
					tok.value = tok.raw.to_f
				else
					lexer.unreadtok ntok
					tok.value = tok.raw.to_i
				end
			else raise tok, 'invalid integer'
			end
		end

		# returns the next value from lexer (parenthesised expression, immediate, variable, unary operators)
		def parse_value(lexer)
			nil while tok = lexer.readtok and tok.type == :space
			return if not tok
			case tok.type
			when :string
				parse_intfloat(lexer, tok)
				val = tok.value || tok.raw
			when :quoted
				if tok.raw[0] != ?'
					lexer.unreadtok tok
					return
				end
				s = tok.value || tok.raw[1..-2]	# raise tok, 'need ppcessing !'
				s = s.reverse if lexer.respond_to? :program and lexer.program and lexer.program.cpu and lexer.program.cpu.endianness == :little
				val = s.unpack('C*').inject(0) { |sum, c| (sum << 8) | c }
			when :punct
				case tok.raw
				when '('
					nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
					lexer.unreadtok ntok
					val = parse(lexer)
					nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
					raise tok, "syntax error, no ) found after #{val.inspect}, got #{ntok.inspect}" if not ntok or ntok.type != :punct or ntok.raw != ')'
				when '!', '+', '-', '~'
					nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
					lexer.unreadtok ntok
					raise tok, 'need expression after unary operator' if not val = parse_value(lexer)
					val = Expression[tok.raw.to_sym, val]
				when '.'
					parse_intfloat(lexer, tok)
					if not tok.value
						lexer.unreadtok tok
						return
					end
					val = tok.value
				else
					lexer.unreadtok tok
					return
				end
			else
				lexer.unreadtok tok
				return
			end
			nil while tok = lexer.readtok and tok.type == :space
			lexer.unreadtok tok
			val
		end

		# for boolean operators, true is 1 (or anything != 0), false is 0
		def parse(lexer)
			opstack = []
			stack = []

			return if not e = parse_value(lexer)

			stack << e

			while op = readop(lexer)
				nil while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
				lexer.unreadtok ntok
				until opstack.empty? or OP_PRIO[op.value][opstack.last]
					stack << new(opstack.pop, stack.pop, stack.pop)
				end
				
				opstack << op.value
				
				raise op, 'need rhs' if not e = parse_value(lexer)

				stack << e
			end

			until opstack.empty?
				stack << new(opstack.pop, stack.pop, stack.pop)
			end

			Expression[stack.first]
		end

		# same as parsing an expression, but return the array of tokens instead of the Expression
		def parse_toks(lexer)
			raise lexer.readtok, 'invalid expression' if not p1 = parse_value_toks(lexer)
			while p2 = readop(lexer)
				p1 << p2
				while ntok = lexer.readtok and (ntok.type == :space or ntok.type == :eol)
					p1 << ntok
				end
				lexer.unreadtok ntok
				p3 = parse_value_toks(lexer)
				raise p1.last, 'no right hand side expression member' if not p3
				p1.concat p3
			end
			p1
		end

		def parse_value_toks(lexer)
			ret = []
			cancel = proc { ret.reverse_each { |t| lexer.unreadtok t } ; return }

			tok = nil
			ret << tok while tok = lexer.readtok and tok.type == :space
			cancel[] if not tok
			ret << tok
			otok = tok
			case tok.type
			when :string
				parse_intfloat(lexer, tok)
			when :quoted
				cancel[] if tok.raw[0] != ?'	# singlequoted only
			when :punct
				case tok.raw
				when '('
					ret << tok while tok = lexer.readtok and (tok.type == :space or tok.type == :eol)
					lexer.unreadtok tok
					ret.concat parse_toks(lexer)
					ret << tok while tok = lexer.readtok and (tok.type == :space or tok.type == :eol)
					raise otok, 'syntax error, no ) found' if not tok = lexer.readtok or tok.type != :punct or tok.raw != ')'
					ret << tok
				when '!', '+', '-', '~'
					# unary operators
					raise otok, 'need expression after unary operator' if not val = parse_value_toks(lexer)
					ret.concat val
				when '.'
					parse_intfloat(lexer, tok)
					cancel[] if not tok.value
				else cancel[]
				end
			else cancel[]
			end
			ret << tok while tok = lexer.readtok and tok.type == :space
			lexer.unreadtok tok
			ret
		end

	end
end
end
