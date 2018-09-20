module Msf::RPC::JSON::V2_0
  class RpcTest

    def initialize
      r = Random.new
      @rand_num = r.rand(0..100)
      $stderr.puts("Msf::RPC::JSON::V2_0::RpcTest.initialize(): @rand_num=#{@rand_num}")
    end

    def self.add(x, y)
      result = x + y
      $stderr.puts("Msf::RPC::JSON::V2_0::RpcTest.add(): x=#{x}, y=#{y}, result=#{result}")

      result
    end

    def get_instance_rand_num
      $stderr.puts("Msf::RPC::JSON::V2_0::RpcTest instance.get_instance_rand_num(): @rand_num=#{@rand_num}")

      @rand_num
    end

    def add_instance_rand_num(x)
      @rand_num = @rand_num + x
      $stderr.puts("Msf::RPC::JSON::V2_0::RpcTest instance.add_instance_rand_num(): x=#{x}, @rand_num=#{@rand_num}")

      @rand_num
    end
  end
end