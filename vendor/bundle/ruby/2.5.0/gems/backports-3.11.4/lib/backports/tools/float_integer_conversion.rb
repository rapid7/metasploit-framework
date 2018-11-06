module Backports
  class << self
    def float_to_integer(float)
      map_via_packing(float, 'D', 'q')
    end

    def integer_to_float(int)
      map_via_packing(int, 'q', 'D')
    end

    private
    def map_via_packing(nb, pack, unpack)
      result, = [nb.abs].pack(pack).unpack(unpack)
      nb < 0 ? -result : result
    end
  end
end
