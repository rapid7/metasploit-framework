#!/usr/bin/ruby

require 'test/unit'
require 'rex/proto/dcerpc'
require 'rex/proto/dcerpc/uuid.rb.ut'
require 'rex/proto/dcerpc/response.rb.ut'
require 'rex/proto/dcerpc/packet.rb.ut'
require 'rex/proto/dcerpc/ndr.rb.ut'

class Rex::Proto::DCERPC::TestSuite
    def self.suite
        suite = Test::Unit::TestSuite.new("Rex::Proto::DCERPC::TestSuite")

        suite << Rex::Proto::DCERPC::UUID::UnitTest.suite
        suite << Rex::Proto::DCERPC::Response::UnitTest.suite
        suite << Rex::Proto::DCERPC::Packet::UnitTest.suite
        suite << Rex::Proto::DCERPC::NDR::UnitTest.suite

        return suite
    end
end
