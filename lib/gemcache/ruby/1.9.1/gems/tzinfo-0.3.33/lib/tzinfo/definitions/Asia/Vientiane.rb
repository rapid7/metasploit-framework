module TZInfo
  module Definitions
    module Asia
      module Vientiane
        include TimezoneDefinition
        
        timezone 'Asia/Vientiane' do |tz|
          tz.offset :o0, 24624, 0, :LMT
          tz.offset :o1, 25580, 0, :SMT
          tz.offset :o2, 25200, 0, :ICT
          tz.offset :o3, 28800, 0, :ICT
          
          tz.transition 1906, 6, :o1, 483474043, 200
          tz.transition 1911, 3, :o2, 2612634701, 1080
          tz.transition 1912, 4, :o3, 58068557, 24
          tz.transition 1931, 4, :o2, 14558773, 6
        end
      end
    end
  end
end
