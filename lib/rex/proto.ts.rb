#!/usr/bin/ruby

require 'test/unit'
require 'rex/proto/smb.ts'
require 'rex/proto/dcerpc.ts'
require 'rex/proto/http.ts'

class Rex::Proto::DCERPC::TestSuite
    def self.suite
        suite = Test::Unit::TestSuite.new("Rex::Proto::DCERPC::TestSuite")

        suite << Rex::Proto::SMB::TestSuite.suite
        suite << Rex::Proto::DCERPC::TestSuite.suite
        suite << Rex::Proto::HTTP::TestSuite.suite

        return suite
    end
end
