require File.expand_path("../helper", __FILE__)

module Sawyer
  class RelationTest < TestCase
    def test_builds_relation_from_hash
      hash = {:href => '/users/1', :method => 'post'}
      rel  = Sawyer::Relation.from_link(nil, :self, hash)

      assert_equal :self,      rel.name
      assert_equal '/users/1', rel.href
      assert_equal :post,      rel.method
      assert_equal [:post],    rel.available_methods.to_a
    end

    def test_builds_multiple_rels_from_multiple_methods
      index = {
        'comments' => {:href => '/comments', :method => 'get,post'}
      }

      rels = Sawyer::Relation.from_links(nil, index)
      assert_equal 1, rels.size
      assert_equal [:comments], rels.keys

      assert rel = rels[:comments]
      assert_equal '/comments',   rel.href
      assert_equal :get,          rel.method
      assert_equal [:get, :post], rel.available_methods.to_a
      assert_kind_of Addressable::Template, rel.href_template
    end

    def test_builds_rels_from_hash
      index = {
        'self' => '/users/1'
      }

      rels = Sawyer::Relation.from_links(nil, index)

      assert_equal 1, rels.size
      assert_equal [:self], rels.keys
      assert rel = rels[:self]
      assert_equal :self,      rel.name
      assert_equal '/users/1', rel.href
      assert_equal :get,       rel.method
      assert_equal [:get],     rel.available_methods.to_a
      assert_kind_of Addressable::Template, rel.href_template
    end

    def test_builds_rels_from_hash_index
      index = {
        'self' => {:href => '/users/1'}
      }

      rels = Sawyer::Relation.from_links(nil, index)

      assert_equal 1, rels.size
      assert_equal [:self], rels.keys
      assert rel = rels[:self]
      assert_equal :self,      rel.name
      assert_equal '/users/1', rel.href
      assert_equal :get,       rel.method
      assert_equal [:get],     rel.available_methods.to_a
      assert_kind_of Addressable::Template, rel.href_template
    end

    def test_builds_rels_from_nil
      rels = Sawyer::Relation.from_links nil, nil
      assert_equal 0,  rels.size
      assert_equal [], rels.keys
    end

    def test_relation_api_calls
      agent = Sawyer::Agent.new "http://foo.com/a/" do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test do |stubs|
          stubs.get '/a/1' do
            [200, {}, '{}']
          end
          stubs.delete '/a/1' do
            [204, {}, '{}']
          end
        end
      end

      rel = Sawyer::Relation.new agent, :self, "/a/1", "get,put,delete"
      assert_equal :get, rel.method
      [:get, :put, :delete].each do |m|
        assert rel.available_methods.include?(m), "#{m.inspect} is not available: #{rel.available_methods.inspect}"
      end

      assert_equal 200, rel.call.status
      assert_equal 200, rel.call(:method => :head).status
      assert_equal 204, rel.call(nil, :method => :delete).status
      assert_raises ArgumentError do
        rel.call nil, :method => :post
      end

      assert_equal 200, rel.head.status
      assert_equal 200, rel.get.status
      assert_equal 204, rel.delete.status

      assert_raises ArgumentError do
        rel.post
      end
    end

    def test_relation_api_calls_with_uri_tempate
      agent = Sawyer::Agent.new "http://foo.com/a" do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test do |stubs|
          stubs.get '/octocat/hello' do |env|
            assert_equal "a=1&b=2", env[:url].query
            [200, {}, '{}']
          end

          stubs.get '/a' do
            [404, {}, '{}']
          end
        end
      end

      rel = Sawyer::Relation.new agent, :repo, "{/user,repo}{?a,b}"

      assert_equal '', rel.href
      assert_equal '/octocat', rel.href(:user => :octocat)

      assert_equal 404, rel.get.status
      assert_equal 200, rel.get(:uri => {'user' => 'octocat', 'repo' => 'hello', 'a' => 1, 'b' => 2}).status
    end

    def test_handles_invalid_uri
      hash = {:href => '/this has spaces', :method => 'post'}
      rel  = Sawyer::Relation.from_link(nil, :self, hash)

      assert_equal :self,      rel.name
      assert_equal '/this has spaces', rel.href
    end

    def test_allows_all_methods_when_not_in_strict_mode

      agent = Sawyer::Agent.new "http://foo.com/a/", :allow_undefined_methods => true do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test do |stubs|
          stubs.get '/a/1' do
            [200, {}, '{}']
          end
          stubs.delete '/a/1' do
            [204, {}, '{}']
          end
          stubs.post '/a/1' do
            [200, {}, '{}']
          end
          stubs.put '/a/1' do
            [204, {}, '{}']
          end
        end
      end

      rel = Sawyer::Relation.new agent, :self, "/a/1"
      assert_equal 200, rel.get.status
      assert_equal 200, rel.post.status
      assert_equal 204, rel.put.status
      assert_equal 204, rel.delete.status
    end

    def test_map_inspect
      map = Sawyer::Relation::Map.new
      hash = {:href => '/users/1', :method => 'post'}
      rel  = Sawyer::Relation.from_link(nil, :self, hash)
      map << rel

      assert_equal "{:self_url=>\"/users/1\"}", map.inspect
    end
  end
end
