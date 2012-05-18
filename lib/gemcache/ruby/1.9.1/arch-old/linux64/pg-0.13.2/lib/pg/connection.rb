#!/usr/bin/env ruby

require 'pg' unless defined?( PG )

# The PG connection class.
class PG::Connection

	# The order the options are passed to the ::connect method.
	CONNECT_ARGUMENT_ORDER = %w[host port options tty dbname user password]


	### Quote the given +value+ for use in a connection-parameter string.
	def self::quote_connstr( value )
		return "'" + value.to_s.gsub( /[\\']/ ) {|m| '\\' + m } + "'"
	end


	### Parse the connection +args+ into a connection-parameter string. See PG::Connection.new
	### for valid arguments.
	def self::parse_connect_args( *args )
		return '' if args.empty?

		# This will be swapped soon for code that makes options like those required for
		# PQconnectdbParams()/PQconnectStartParams(). For now, stick to an options string for
		# PQconnectdb()/PQconnectStart().
		connopts = []

		# Handle an options hash first
		if args.last.is_a?( Hash )
			opthash = args.pop 
			opthash.each do |key, val|
				connopts.push( "%s=%s" % [key, PG::Connection.quote_connstr(val)] )
			end
		end

		# Option string style
		if args.length == 1 && args.first.to_s.index( '=' )
			connopts.unshift( args.first )

		# Append positional parameters
		else
			args.each_with_index do |val, i|
				next unless val # Skip nil placeholders

				key = CONNECT_ARGUMENT_ORDER[ i ] or
					raise ArgumentError, "Extra positional parameter %d: %p" % [ i+1, val ]
				connopts.push( "%s=%s" % [key, PG::Connection.quote_connstr(val.to_s)] )
			end
		end

		return connopts.join(' ')
	end

end # class PG::Connection

# Backward-compatible alias
PGconn = PG::Connection

