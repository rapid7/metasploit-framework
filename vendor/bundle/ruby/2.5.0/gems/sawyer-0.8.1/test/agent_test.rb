require File.expand_path("../helper", __FILE__)

require 'faraday/adapter/test'

module Sawyer
  class AgentTest < TestCase

    class InlineRelsParser
      def parse(data)
        links = {}
        data.keys.select {|k| k[/_url$/] }.each {|k| links[k.to_s.gsub(/_url$/, '')] = data.delete(k) }

        return data, links
      end
    end

    def setup
      @stubs = Faraday::Adapter::Test::Stubs.new
      @agent = Sawyer::Agent.new "http://foo.com/a/" do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test, @stubs
      end
    end

    def test_accesses_root_relations
      @stubs.get '/a/' do |env|
        assert_equal 'foo.com', env[:url].host

        [200, {'Content-Type' => 'application/json'}, Sawyer::Agent.encode(
          :_links => {
            :users => {:href => '/users'}})]
      end

      assert_equal 200, @agent.root.status

      assert_equal '/users', @agent.rels[:users].href
      assert_equal :get,     @agent.rels[:users].method
    end

    def test_allows_custom_rel_parsing
      @stubs.get '/a/' do |env|
        assert_equal 'foo.com', env[:url].host

        [200, {'Content-Type' => 'application/json'}, Sawyer::Agent.encode(
          :url => '/',
          :users_url => '/users',
          :repos_url => '/repos')]
      end

      agent = Sawyer::Agent.new "http://foo.com/a/" do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test, @stubs
      end
      agent.links_parser = InlineRelsParser.new

      assert_equal 200, agent.root.status

      assert_equal '/users', agent.rels[:users].href
      assert_equal :get,     agent.rels[:users].method
      assert_equal '/repos', agent.rels[:repos].href
      assert_equal :get,     agent.rels[:repos].method

    end

    def test_saves_root_endpoint
      @stubs.get '/a/' do |env|
        [200, {}, '{}']
      end

      assert_kind_of Sawyer::Response, @agent.root
      refute_equal @agent.root.time, @agent.start.time
    end

    def test_starts_a_session
      @stubs.get '/a/' do |env|
        assert_equal 'foo.com', env[:url].host

        [200, {'Content-Type' => 'application/json'}, Sawyer::Agent.encode(
          :_links => {
            :users => {:href => '/users'}})]
      end

      res = @agent.start

      assert_equal 200, res.status
      assert_kind_of Sawyer::Resource, resource = res.data

      assert_equal '/users', resource.rels[:users].href
      assert_equal :get,     resource.rels[:users].method
    end

    def test_requests_with_body_and_options
      @stubs.post '/a/b/c' do |env|
        assert_equal '{"a":1}', env[:body]
        assert_equal 'abc',     env[:request_headers]['x-test']
        assert_equal 'foo=bar', env[:url].query
        [200, {}, "{}"]
      end

      res = @agent.call :post, 'b/c' , {:a => 1},
        :headers => {"X-Test" => "abc"},
        :query   => {:foo => 'bar'}
      assert_equal 200, res.status
    end

    def test_requests_with_body_and_options_to_get
      @stubs.get '/a/b/c' do |env|
        assert_nil env[:body]
        assert_equal 'abc',     env[:request_headers]['x-test']
        assert_equal 'foo=bar', env[:url].query
        [200, {}, "{}"]
      end

      res = @agent.call :get, 'b/c' , {:a => 1},
        :headers => {"X-Test" => "abc"},
        :query   => {:foo => 'bar'}
      assert_equal 200, res.status
    end

    def test_encodes_and_decodes_times
      time = Time.at(Time.now.to_i)
      data = {
        :a => 1,
        :b => true,
        :c => 'c',
        :created_at => time,
        :published_at => nil,
        :updated_at => "An invalid date",
        :pub_date => time,
        :subscribed_at => time.to_i,
        :lost_at => time.to_f,
        :first_date => false,
        :validate => true
      }
      data = [data.merge(:foo => [data])]
      encoded = Sawyer::Agent.encode(data)
      decoded = Sawyer::Agent.decode(encoded)

      2.times do
        assert_equal 1, decoded.size
        decoded = decoded.shift

        assert_equal 1, decoded[:a]
        assert_equal true, decoded[:b]
        assert_equal 'c', decoded[:c]
        assert_equal time, decoded[:created_at], "Did not parse created_at as Time"
        assert_nil decoded[:published_at]
        assert_equal "An invalid date", decoded[:updated_at]
        assert_equal time, decoded[:pub_date], "Did not parse pub_date as Time"
        assert_equal true, decoded[:validate]
        assert_equal time, decoded[:subscribed_at], "Did not parse subscribed_at as Time"
        assert_equal time, decoded[:lost_at], "Did not parse lost_at as Time"
        assert_equal false, decoded[:first_date], "Parsed first_date"
        decoded = decoded[:foo]
      end
    end

    def test_does_not_encode_non_json_content_types
      @stubs.get '/a/' do |env|
        assert_equal 'foo.com', env[:url].host

        [200, {'Content-Type' => 'text/plain'}, "This is plain text"]
      end
      res = @agent.call :get, '/a/',
        :headers => {"Accept" => "text/plain"}
      assert_equal 200, res.status

      assert_equal "This is plain text", res.data
    end

    def test_handle_yaml_dump_and_load
      require 'yaml'
      res = Agent.new 'http://example.com', :a => 1
      YAML.load(YAML.dump(res))
    end

    def test_handle_marshal_dump_and_load
      res = Agent.new 'http://example.com', :a => 1
      Marshal.load(Marshal.dump(res))
    end

    def test_blank_response_doesnt_raise
      @stubs.get "/a/" do |env|
        assert_equal "foo.com", env[:url].host
        [200, { "Content-Type" => "application/json" }, " "]
      end

      agent = Sawyer::Agent.new "http://foo.com/a/" do |conn|
        conn.adapter :test, @stubs
      end

      assert_equal 200, agent.root.status
    end
  end
end
