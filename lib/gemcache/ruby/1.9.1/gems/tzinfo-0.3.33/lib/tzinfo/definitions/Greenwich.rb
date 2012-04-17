module TZInfo
  module Definitions
    module Greenwich
      include TimezoneDefinition
      
      linked_timezone 'Greenwich', 'Etc/GMT'
    end
  end
end
