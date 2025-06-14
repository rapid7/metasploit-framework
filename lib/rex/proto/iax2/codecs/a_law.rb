# -*- coding: binary -*-
module Rex
module Proto
module IAX2
module Codecs
class ALaw < G711

  def self.decode(buff)
    buff.unpack("C*").map{ |x| LOOKUP_ALAW2LIN16[x] }.pack('v*')
  end

end
end
end
end
end
