#!/usr/bin/env ruby

require 'pg' unless defined?( PG )


class PG::Result
	
end # class PG::Result

# Backward-compatible alias
PGresult = PG::Result
