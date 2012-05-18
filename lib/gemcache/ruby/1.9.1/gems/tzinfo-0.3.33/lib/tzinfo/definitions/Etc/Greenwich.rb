module TZInfo
  module Definitions
    module Etc
      module Greenwich
        include TimezoneDefinition
        
        linked_timezone 'Etc/Greenwich', 'Etc/GMT'
      end
    end
  end
end
