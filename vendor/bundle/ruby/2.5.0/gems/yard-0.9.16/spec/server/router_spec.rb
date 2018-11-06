# frozen_string_literal: true
require File.dirname(__FILE__) + '/spec_helper'

class MyRouterSpecRouter < Router
  def docs_prefix; 'mydocs/foo' end
  def list_prefix; 'mylist/foo' end
  def search_prefix; 'mysearch/foo' end

  def check_static_cache; nil end
end

RSpec.describe YARD::Server::Router do
  before do
    @adapter = mock_adapter
    @projects = @adapter.libraries['project']
    @request = mock_request
  end

  describe "#parse_library_from_path" do
    def parse(*args)
      @request.path_info = '/' + args.join('/')
      @router = MyRouterSpecRouter.new(@adapter)
      @router.request = @request
      @router.parse_library_from_path(args.flatten)
    end

    it "parses library and version name out of path" do
      expect(parse('project', '1.0.0')).to eq [@projects[0], []]
      expect(@request.version_supplied).to be true
    end

    it "parses library and use latest version if version is not supplied" do
      expect(parse('project')).to eq [@projects[1], []]
      expect(@request.version_supplied).to be false
    end

    it "parses library and use latest version if next component is not a version" do
      expect(parse('project', 'notaversion')).to eq [@projects[1], ['notaversion']]
      expect(@request.version_supplied).to be false
    end

    it "returns nil library if no library is found" do
      expect(parse('notproject')).to eq [nil, ['notproject']]
    end

    it "does not parse library or version if single_library == true" do
      allow(@adapter).to receive(:options).and_return(:single_library => true)
      expect(parse('notproject')).to eq [@projects[0], ['notproject']]
    end
  end

  describe "#route" do
    def route_to(route, command, script_name = '')
      req = mock_request(route, script_name)
      router = MyRouterSpecRouter.new(@adapter)
      expect(command).to receive(:new) do |*args|
        @command = command.allocate
        @command.send(:initialize, *args)
        class << @command; define_method(:call) {|*| self } end
        @command
      end
      router.call(req)
    end

    it "routes /docs/OBJECT to object if single_library = true" do
      allow(@adapter).to receive(:options).and_return(:single_library => true)
      route_to('/mydocs/foo/FOO', DisplayObjectCommand)
    end

    it "routes /docs" do
      route_to('/mydocs/foo', LibraryIndexCommand)
    end

    it "routes /docs as index for library if single_library == true" do
      allow(@adapter).to receive(:options).and_return(:single_library => true)
      route_to('/mydocs/foo/', DisplayObjectCommand)
    end

    it "routes /docs/name/version" do
      route_to('/mydocs/foo/project/1.0.0', DisplayObjectCommand)
      expect(@command.library).to eq @projects[0]
    end

    it "routes /docs/name/ to latest version of library" do
      route_to('/mydocs/foo/project', DisplayObjectCommand)
      expect(@command.library).to eq @projects[1]
    end

    it "routes /list/name/version/class" do
      route_to('/mylist/foo/project/1.0.0/class', ListCommand)
      expect(@command.library).to eq @projects[0]
    end

    it "routes /list/name/version/methods" do
      route_to('/mylist/foo/project/1.0.0/methods', ListCommand)
      expect(@command.library).to eq @projects[0]
    end

    it "routes /list/name/version/files" do
      route_to('/mylist/foo/project/1.0.0/files', ListCommand)
      expect(@command.library).to eq @projects[0]
    end

    it "routes /list/name to latest version of library" do
      route_to('/mylist/foo/project/class', ListCommand)
      expect(@command.library).to eq @projects[1]
    end

    it "routes /search/name/version" do
      route_to('/mysearch/foo/project/1.0.0', SearchCommand)
      expect(@command.library).to eq @projects[0]
    end

    it "routes /search/name to latest version of library" do
      route_to('/mysearch/foo/project', SearchCommand)
      expect(@command.library).to eq @projects[1]
    end

    it "searches static files for non-existent library" do
      route_to('/mydocs/foo/notproject', RootRequestCommand)
    end
  end
end
