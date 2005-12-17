#!/usr/bin/env ruby

require 'test/unit'

require 'rex/proto/http'
require 'rex/proto/http/client.rb.ut'
require 'rex/proto/http/server.rb.ut'
require 'rex/proto/http/packet.rb.ut'
require 'rex/proto/http/request.rb.ut'
require 'rex/proto/http/response.rb.ut'
require 'rex/proto/http/handler/erb.rb.ut'
require 'rex/proto/http/handler/proc.rb.ut'

class Rex::Proto::Http::TestSuite
    def self.suite
        suite = Test::Unit::TestSuite.new("Rex::Proto::Http::TestSuite")

        suite << Rex::Proto::Http::Client::UnitTest.suite
        suite << Rex::Proto::Http::Server::UnitTest.suite
        suite << Rex::Proto::Http::Packet::UnitTest.suite
        suite << Rex::Proto::Http::Request::UnitTest.suite
        suite << Rex::Proto::Http::Response::UnitTest.suite
        suite << Rex::Proto::Http::Handler::ERB::UnitTest.suite
        suite << Rex::Proto::Http::Handler::Proc::UnitTest.suite

        return suite
    end
end

