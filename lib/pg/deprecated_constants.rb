# Slightly modified version of a workaround written by Eliot Sykes https://stackoverflow.com/a/51232774
# File: lib/pg/deprecated_constants.rb
#
# This file overrides the pg gem's pg/deprecated_constants.rb file and so
# its warning message is not printed. Avoiding this warning message helps
# clean up the app startup and test output.
#
# This behaviour relies on lib/ being ahead of the pg gem in $LOAD_PATH and
# these lines from the pg gem's lib/pg.rb file:
# autoload :PGError,  'pg/deprecated_constants'
# autoload :PGconn,   'pg/deprecated_constants'
# autoload :PGresult, 'pg/deprecated_constants'
#
# Your config/application.rb may need to modify autoload_paths to ensure
# the lib/ dir is ahead of the pg gem install path in $LOAD_PATH:
#
# config.autoload_paths << Rails.root.join('lib')
#
if PG::VERSION != '0.21.0' || ActiveRecord.version.to_s != '4.2.11.1'
  puts <<MSG
-----------------------------------------------------------------------------------
The pg and/or activerecord gem version has changed, meaning deprecated pg constants
may no longer be in use, so try deleting this file to see if the
'The PGconn, PGresult, and PGError constants are deprecated...' message has gone:
#{__FILE__}
-----------------------------------------------------------------------------------

MSG
end

# Declare the deprecated constants as is done in the original 
# pg/deprecated_constants.rb so they can still be used by older
# versions of gems such as activerecord.
PGconn   = PG::Connection
PGresult = PG::Result
PGError  = PG::Error