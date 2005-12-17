#!/usr/bin/env ruby

require 'test/unit'
require 'rex/proto/dcerpc'
require 'rex/proto/dcerpc/uuid.rb.ut'
require 'rex/proto/dcerpc/response.rb.ut'
require 'rex/proto/dcerpc/packet.rb.ut'

require 'rex/proto/smb/client.rb.ut.rb'
require 'rex/proto/smb/constants.rb.ut.rb'
require 'rex/proto/smb/crypt.rb.ut.rb'
require 'rex/proto/smb/simpleclient.rb.ut.rb'
require 'rex/proto/smb/utils.rb.ut.rb'

class Rex::Proto::SMB::TestSuite
    def self.suite
        suite = Test::Unit::TestSuite.new("Rex::Proto::SMB::TestSuite")

        suite << Rex::Proto::SMB::Client::UnitTest.suite
        suite << Rex::Proto::SMB::Constants::UnitTest.suite
        suite << Rex::Proto::SMB::Crypt::UnitTest.suite
        suite << Rex::Proto::SMB::SimpleClient::UnitTest.suite
        suite << Rex::Proto::SMB::Utils::UnitTest.suite

        return suite
    end
end

