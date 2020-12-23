module Msf::RPC::JSON::V2_0
  # Receiver class for demonstration RPC version 2.0.
  class RpcTest

    def initialize
      r = Random.new
      @rand_num = r.rand(0..100)
    end

    def self.add(x, y)
      x + y
    end

    def get_instance_rand_num
      @rand_num
    end

    def add_instance_rand_num(x)
      @rand_num = @rand_num + x

      @rand_num
    end
  end
end