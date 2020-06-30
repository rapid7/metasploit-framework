#
# PostgreSQL injection
#
module Msf::Exploit::SQLi::PostgreSQLi
end

require 'msf/core/exploit/sqli/postgresqli/common'
require 'msf/core/exploit/sqli/postgresqli/boolean_based_blind'
require 'msf/core/exploit/sqli/postgresqli/time_based_blind'
