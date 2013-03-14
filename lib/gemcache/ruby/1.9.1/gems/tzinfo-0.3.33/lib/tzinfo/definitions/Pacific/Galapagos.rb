module TZInfo
  module Definitions
    module Pacific
      module Galapagos
        include TimezoneDefinition
        
        timezone 'Pacific/Galapagos' do |tz|
          tz.offset :o0, -21504, 0, :LMT
          tz.offset :o1, -18000, 0, :ECT
          tz.offset :o2, -21600, 0, :GALT
          
          tz.transition 1931, 1, :o1, 1091854237, 450
          tz.transition 1986, 1, :o2, 504939600
        end
      end
    end
  end
end
