module Msf


##
#
# This module defines all of the DB database tables
# and creates ActiveRecord objects for each one of them
#
##

class DBManager

# Host object definition
class Host < ActiveRecord::Base
end

# Service object definition
class Service < ActiveRecord::Base
end

end
end
