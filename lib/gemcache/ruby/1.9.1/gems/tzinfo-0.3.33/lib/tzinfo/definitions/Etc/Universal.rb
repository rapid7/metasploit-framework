module TZInfo
  module Definitions
    module Etc
      module Universal
        include TimezoneDefinition
        
        linked_timezone 'Etc/Universal', 'Etc/UTC'
      end
    end
  end
end
