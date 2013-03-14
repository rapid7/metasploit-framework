module TZInfo
  module Definitions
    module Zulu
      include TimezoneDefinition
      
      linked_timezone 'Zulu', 'Etc/UTC'
    end
  end
end
