require File.expand_path("../helper", __FILE__)

module Sawyer
  class ResourceTest < TestCase

    def setup
      @stubs = Faraday::Adapter::Test::Stubs.new
      @agent = Sawyer::Agent.new "http://foo.com/a/" do |conn|
        conn.builder.handlers.delete(Faraday::Adapter::NetHttp)
        conn.adapter :test, @stubs
      end
    end

    def test_accessible_keys
      res = Resource.new @agent, :a => 1,
        :_links => {:self => {:href => '/'}}

      assert_equal 1, res.a
      assert res.rels[:self]
      assert_equal @agent, res.agent
      assert_equal 1, res.fields.size
      assert res.fields.include?(:a)
    end

    def test_clashing_keys
      res = Resource.new @agent, :agent => 1, :rels => 2, :fields => 3,
        :_links => {:self => {:href => '/'}}

      assert_equal 1, res.agent
      assert_equal 2, res.rels
      assert_equal 3, res.fields

      assert res._rels[:self]
      assert_equal @agent, res._agent
      assert_equal 3, res._fields.size
      [:agent, :rels, :fields].each do |f|
        assert res._fields.include?(f)
      end
    end

    def test_nested_object
      res = Resource.new @agent,
        :user   => {:id => 1, :_links => {:self => {:href => '/users/1'}}},
        :_links => {:self => {:href => '/'}}

      assert_equal '/', res.rels[:self].href
      assert_kind_of Resource, res.user
      assert_equal 1, res.user.id
      assert_equal '/users/1', res.user.rels[:self].href
    end

    def test_nested_collection
      res = Resource.new @agent,
        :users  => [{:id => 1, :_links => {:self => {:href => '/users/1'}}}],
        :_links => {:self => {:href => '/'}}

      assert_equal '/', res.rels[:self].href
      assert_kind_of Array, res.users

      assert user = res.users.first
      assert_kind_of Resource, user
      assert_equal 1, user.id
      assert_equal '/users/1', user.rels[:self].href
    end

    def test_attribute_predicates
      res = Resource.new @agent, :a => 1, :b => true, :c => nil, :d => false

      assert  res.a?
      assert  res.b?
      assert !res.c?
      assert !res.d?
    end

    def test_attribute_setter
      res = Resource.new @agent, :a => 1
      assert_equal 1, res.a
      assert !res.key?(:b)

      res.b = 2
      assert_equal 2, res.b
      assert res.key?(:b)
    end

    def test_dynamic_attribute_methods_from_getter
      res = Resource.new @agent, :a => 1
      assert res.key?(:a)
      assert res.respond_to?(:a)
      assert res.respond_to?(:a=)

      assert_equal 1, res.a
      assert res.respond_to?(:a)
      assert res.respond_to?(:a=)
    end

    def test_nillable_attribute_getters
      res = Resource.new @agent, :a => 1
      assert !res.key?(:b)
      assert !res.respond_to?(:b)
      assert !res.respond_to?(:b=)
      assert_nil res.b
      res.b
    end

    def test_dynamic_attribute_methods_from_setter
      res = Resource.new @agent, :a => 1
      assert !res.key?(:b)
      assert !res.respond_to?(:b)
      assert !res.respond_to?(:b=)

      res.b = 1
      assert res.key?(:b)
      assert res.respond_to?(:b)
      assert res.respond_to?(:b=)
    end

    def test_attrs
      res = Resource.new @agent, :a => 1
      hash = {:a => 1 }
      assert_equal hash, res.attrs
    end

    def test_to_h
      res = Resource.new @agent, :a => 1
      hash = {:a => 1 }
      assert_equal hash, res.to_h
    end

    def test_to_h_with_nesting
      res = Resource.new @agent, :a => {:b => 1}
      hash = {:a => {:b => 1}}
      assert_equal hash, res.to_h
    end

    def test_to_attrs_for_sawyer_resource_arrays
      res = Resource.new @agent, :a => 1, :b => [Resource.new(@agent, :a => 2)]
      hash = {:a => 1, :b => [{:a => 2}]}
      assert_equal hash, res.to_attrs
    end

    def test_handle_hash_notation_with_string_key
      res = Resource.new @agent, :a => 1
      assert_equal 1, res['a']

      res[:b] = 2
      assert_equal 2, res.b
    end

    def test_simple_rel_parsing
      @agent.links_parser = Sawyer::LinkParsers::Simple.new
      res = Resource.new @agent,
        :url => '/',
        :user   => {
          :id => 1,
          :url => '/users/1',
          :followers_url => '/users/1/followers'
        }

      assert_equal '/', res.rels[:self].href
      assert_kind_of Resource, res.user
      assert_equal '/', res.url
      assert_equal 1, res.user.id
      assert_equal '/users/1', res.user.rels[:self].href
      assert_equal '/users/1', res.user.url
      assert_equal '/users/1/followers', res.user.rels[:followers].href
      assert_equal '/users/1/followers', res.user.followers_url
    end

    def test_handle_yaml_dump
      require 'yaml'
      res = Resource.new @agent, :a => 1
      YAML.dump(res)
    end

    def test_handle_marshal_dump
      dump = Marshal.dump(Resource.new(@agent, :a => 1))
      resource = Marshal.load(dump)
      assert_equal 1, resource.a
    end

    def test_inspect
      resource = Resource.new @agent, :a => 1
      assert_equal "{:a=>1}", resource.inspect
    end

    def test_each
      resource = Resource.new @agent, { :a => 1, :b => 2 }
      output = []
      resource.each { |k,v| output << [k,v] }
      assert_equal [[:a, 1], [:b, 2]], output
    end

    def test_enumerable
      resource = Resource.new @agent, { :a => 1, :b => 2 }
      enum = resource.map
      assert_equal Enumerator, enum.class
    end
  end
end
