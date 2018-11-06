# frozen_string_literal: true
require File.dirname(__FILE__) + "/spec_helper"

class MyDocServerSerializerRouter
  attr_accessor :request
  def docs_prefix; 'PREFIX' end
  def initialize; @request = mock_request end
end

class MockDocServerHelper
  include YARD::Templates::Helpers::BaseHelper
  include YARD::Templates::Helpers::HtmlHelper
  include YARD::Server::DocServerHelper

  attr_accessor :adapter
  attr_accessor :single_library
  attr_accessor :library

  def initialize
    @single_library = false
    @library = LibraryVersion.new('foo')
    @adapter = mock_adapter(:router => MyDocServerSerializerRouter.new)
    @serializer = YARD::Server::DocServerSerializer.new
    @object = YARD::Registry.root
  end

  def options; OpenStruct.new end
end

RSpec.describe YARD::Server::DocServerHelper do
  before do
    @helper = MockDocServerHelper.new
  end

  describe "#url_for" do
    it "does not link to /library/ if single_library = true" do
      @helper.single_library = true
      expect(@helper.url_for(Registry.root)).to eq "/PREFIX/toplevel"
    end

    it "returns /PREFIX/foo/version if foo has a version" do
      @helper.library = LibraryVersion.new('foo', 'bar')
      @helper.adapter.router.request.version_supplied = true
      expect(@helper.url_for(P('A'))).to eq '/PREFIX/foo/bar/A'
    end

    it "uses script name prefix if set" do
      @helper.adapter.router.request.script_name = '/mount/point'
      @helper.library = LibraryVersion.new('foo', 'bar')
      @helper.adapter.router.request.version_supplied = true
      expect(@helper.url_for(P('A'))).to eq '/mount/point/PREFIX/foo/bar/A'
    end
  end

  describe "#url_for_file" do
    it "properly links file objects using file/ prefix" do
      file = CodeObjects::ExtraFileObject.new('a/b/FooBar.md', '')
      expect(@helper.url_for_file(file)).to eq '/PREFIX/foo/file/a/b/FooBar.md'
    end

    it "properly links anchor portion" do
      file = CodeObjects::ExtraFileObject.new('a/b/FooBar.md', '')
      expect(@helper.url_for_file(file, 'anchor')).to eq '/PREFIX/foo/file/a/b/FooBar.md#anchor'
    end

    it "uses script name prefix if set" do
      @helper.adapter.router.request.script_name = '/mount/point'
      file = CodeObjects::ExtraFileObject.new('a/b/FooBar.md', '')
      expect(@helper.url_for_file(file)).to eq '/mount/point/PREFIX/foo/file/a/b/FooBar.md'
    end
  end
end
