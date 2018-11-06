require File.expand_path("../helper", __FILE__)

module Sawyer
  class ResponseTest < TestCase
    def setup
      @now = Time.now
      @stubs = Faraday::Adapter::Test::Stubs.new
      @agent = Sawyer::Agent.new "http://foo.com" do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test, @stubs do |stub|
          stub.get '/' do
            [200, {
              'Content-Type' => 'application/json',
              'Link' =>  '</starred?page=2>; rel="next", </starred?page=19>; rel="last"'
              }, Sawyer::Agent.encode(
              :a => 1,
              :_links => {
                :self => {:href => '/a', :method => 'POST'}
              }
            )]
          end

          stub.get '/emails' do
            emails = %w(rick@example.com technoweenie@example.com)
            [200, {'Content-Type' => 'application/json'}, Sawyer::Agent.encode(emails)]
          end
        end
      end

      @res = @agent.start
      assert_kind_of Sawyer::Response, @res
    end

    def test_gets_status
      assert_equal 200, @res.status
    end

    def test_gets_headers
      assert_equal 'application/json', @res.headers['content-type']
    end

    def test_gets_body
      assert_equal 1, @res.data.a
      assert_equal [:a], @res.data.fields.to_a
    end

    def test_gets_rels
      assert_equal '/starred?page=2', @res.rels[:next].href
      assert_equal :get, @res.rels[:next].method
      assert_equal '/starred?page=19', @res.rels[:last].href
      assert_equal :get, @res.rels[:next].method
      assert_equal '/a',  @res.data.rels[:self].href
      assert_equal :post, @res.data.rels[:self].method
    end

    def test_gets_response_timing
      assert @res.timing > 0
      assert @res.time >= @now
    end

    def test_makes_request_from_relation
      @stubs.post '/a' do
        [201, {'Content-Type' => 'application/json'}, ""]
      end

      res = @res.data.rels[:self].call
      assert_equal 201, res.status
      assert_nil res.data
    end

    def test_handles_arrays_of_strings
      res = @agent.call(:get, '/emails')
      assert_equal 'rick@example.com', res.data.first
    end
  end
end

