module TZInfo
  module Definitions
    module Etc
      module UCT
        include TimezoneDefinition
        
        timezone 'Etc/UCT' do |tz|
          tz.offset :o0, 0, 0, :UCT
          
        end
      end
    end
  end
end
