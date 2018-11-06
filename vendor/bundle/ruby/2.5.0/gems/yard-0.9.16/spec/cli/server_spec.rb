# frozen_string_literal: true

class Server::WebrickAdapter; def start; end end

RSpec.describe YARD::CLI::Server do
  before do
    allow(CLI::Yardoc).to receive(:run)
    @no_verify_libraries = false
    @set_libraries = true
    @no_adapter_mock = false
    @libraries = {}
    @options = {:single_library => true, :caching => false}
    @server_options = {:Port => 8808}
    @adapter = double(:adapter, :setup => nil)
    new_cli
  end

  after(:all) do
    Server::Adapter.shutdown
  end

  def new_cli
    @cli = subject
  end

  def rack_required
    require 'rack'
  rescue LoadError
    pending "rack required for this test"
  end

  def bundler_required
    require 'bundler'
  rescue LoadError
    pending "bundler required for this test"
  end

  def unstub_adapter
    @no_adapter_mock = true
  end

  def run(*args)
    if @set_libraries && @libraries.empty?
      library = Server::LibraryVersion.new(
        File.basename(Dir.pwd), nil, File.expand_path('.yardoc')
      )
      @libraries = {library.name => [library]}
    end
    unless @no_verify_libraries
      @libraries.values.each do |libs|
        libs.each do |lib|
          yfile = File.expand_path(lib.yardoc_file)
          allow(File).to receive(:exist?).with(yfile).and_return(true)
        end
      end
    end
    unless @no_adapter_mock
      allow(@cli).to receive(:adapter).and_return(@adapter)
      expect(@adapter).to receive(:new).
        with(@libraries, @options, @server_options).and_return(@adapter)
      expect(@adapter).to receive(:start)
    end

    @cli.run(*args.flatten)
    assert_libraries @libraries, @cli.libraries
  end

  def assert_libraries(expected_libs, actual_libs)
    expect(actual_libs).to eq expected_libs
    expected_libs.each do |name, libs|
      libs.each_with_index do |expected, i|
        actual = actual_libs[name][i]
        [:source, :source_path, :yardoc_file].each do |m|
          expect(actual.send(m)).to eq expected.send(m)
        end
      end
    end
  end

  # Mocks the existence of a file.
  def mock_file(filename, content = nil)
    allow(File).to receive(:exist?).with(filename).and_return(true)
    allow(File).to receive(:read_binary).with(filename).and_return(content) if content
    filename_e = File.expand_path(filename)
    mock_file(filename_e) unless filename_e == filename
  end

  before :each do
    allow(File).to receive(:exist?).and_call_original
  end

  context 'when .yardopts file exists' do
    before :each do
      Registry.yardoc_file = Registry::DEFAULT_YARDOC_FILE
      allow(File).to receive(:exist?).with(%r{\.yardoc/complete$}).and_return(false)
      allow(Dir).to receive(:pwd).and_return('/path/to/bar')
      allow(Dir).to receive(:chdir).and_yield
      @name = 'bar'
    end

    it "uses .yardoc as the yardoc db if .yardopts doesn't specify an alternate path" do
      mock_file '/path/to/bar/.yardopts', '--protected'
      @libraries[@name] = [Server::LibraryVersion.new(@name, nil, File.expand_path('/path/to/bar/.yardoc'))]
      @libraries.values[0][0].source_path = File.expand_path('/path/to/bar')
      run
    end

    it "uses the yardoc db location specified by .yardopts" do
      allow(File).to receive(:exist?).with(%r{/foo/complete$}).and_return(false)
      mock_file '/path/to/bar/.yardopts', '--db foo'
      @libraries[@name] = [Server::LibraryVersion.new(@name, nil, File.expand_path('/path/to/bar/foo'))]
      @libraries.values[0][0].source_path = File.expand_path('/path/to/bar')
      run
    end

    it "parses .yardopts when the library list is odd" do
      mock_file '/path/to/bar/.yardopts', '--db foo'
      @libraries['a'] = [Server::LibraryVersion.new('a', nil, File.expand_path('/path/to/bar/foo'))]
      @libraries.values[0][0].source_path = File.expand_path('/path/to/bar')
      run 'a'
    end
  end

  context "when .yardopts file doesn't exist" do
    before :each do
      allow(File).to receive(:exist?).with(%r{\.yardoc/complete$}).and_return(false)
      allow(File).to receive(:exist?).with(%r{^(.*[\\/])?\.yardopts$}).and_return(false)
    end

    it "defaults to .yardoc if no library is specified" do
      allow(Dir).to receive(:chdir).and_yield
      expect(Dir).to receive(:pwd).at_least(:once).and_return(File.expand_path('/path/to/foo'))
      @libraries['foo'] = [Server::LibraryVersion.new('foo', nil, File.expand_path('/path/to/foo/.yardoc'))]
      run
    end

    it "uses .yardoc as yardoc file if library list is odd" do
      @libraries['a'] = [Server::LibraryVersion.new('a', nil, File.expand_path('.yardoc'))]
      run 'a'
    end

    it "forces multi library if more than one library is listed" do
      allow(File).to receive(:exist?).with('b').and_return(true)
      @options[:single_library] = false
      @libraries['a'] = [Server::LibraryVersion.new('a', nil, File.expand_path('b'))]
      @libraries['c'] = [Server::LibraryVersion.new('c', nil, File.expand_path('.yardoc'))]
      run %w(a b c)
    end

    it "fails if specified directory does not exist" do
      @set_libraries = false
      allow(File).to receive(:exist?).with('b').and_return(false)
      expect(log).to receive(:warn).with(/Cannot find yardoc db for a: "b"/)
      run %w(a b)
    end
  end

  describe "General options" do
    before do
      allow(File).to receive(:exist?).with(%r{\.yardoc/complete$}).and_return(false)
      allow(File).to receive(:exist?).with(/\.yardopts$/).and_return(false)
    end

    it "accepts -m, --multi-library" do
      @options[:single_library] = false
      run '-m'
      run '--multi-library'
    end

    it "accepts -c, --cache" do
      @options[:caching] = true
      run '-c'
      run '--cache'
    end

    it "accepts -r, --reload" do
      @options[:incremental] = true
      run '-r'
      run '--reload'
    end

    it "accepts -d, --daemon" do
      @server_options[:daemonize] = true
      run '-d'
      run '--daemon'
    end

    it "accepts -B, --bind" do
      @server_options[:Host] = 'example.com'
      run '-B', 'example.com'
      run '--bind', 'example.com'
    end

    it "binds address with WebRick adapter" do
      @server_options[:Host] = 'example.com'
      run '-B', 'example.com', '-a', 'webrick'
      run '--bind', 'example.com', '-a', 'webrick'
    end

    it "binds address with Rack adapter" do
      @server_options[:Host] = 'example.com'
      run '-B', 'example.com', '-a', 'rack'
      run '--bind', 'example.com', '-a', 'rack'
    end

    it "accepts -p, --port" do
      @server_options[:Port] = 10
      run '-p', '10'
      run '--port', '10'
    end

    it "accepts --docroot" do
      @server_options[:DocumentRoot] = Dir.pwd + '/__foo/bar'
      run '--docroot', '__foo/bar'
    end

    it "accepts -a webrick to create WEBrick adapter" do
      expect(@cli).to receive(:adapter=).with(YARD::Server::WebrickAdapter)
      run '-a', 'webrick'
    end

    it "accepts -a rack to create Rack adapter" do
      rack_required
      expect(@cli).to receive(:adapter=).with(YARD::Server::RackAdapter)
      run '-a', 'rack'
    end

    it "defaults to Rack adapter if exists on system" do
      rack_required
      expect(@cli).to receive(:require).with('rubygems').and_return(false)
      expect(@cli).to receive(:require).with('rack').and_return(true)
      expect(@cli).to receive(:adapter=).with(YARD::Server::RackAdapter)
      @cli.send(:select_adapter)
    end

    it "falls back to WEBrick adapter if Rack is not on system" do
      expect(@cli).to receive(:require).with('rubygems').and_return(false)
      expect(@cli).to receive(:require).with('rack').and_raise(LoadError)
      expect(@cli).to receive(:adapter=).with(YARD::Server::WebrickAdapter)
      @cli.send(:select_adapter)
    end

    it "accepts -s, --server" do
      @server_options[:server] = 'thin'
      run '-s', 'thin'
      run '--server', 'thin'
    end

    it "accepts -g, --gems" do
      @no_verify_libraries = true
      @options[:single_library] = false
      @libraries['gem1'] = [Server::LibraryVersion.new('gem1', '1.0.0', nil, :gem)]
      @libraries['gem2'] = [Server::LibraryVersion.new('gem2', '1.0.0', nil, :gem)]
      gem1 = double(:gem1, :name => 'gem1', :version => '1.0.0', :full_gem_path => '/path/to/foo')
      gem2 = double(:gem2, :name => 'gem2', :version => '1.0.0', :full_gem_path => '/path/to/bar')
      specs = {'gem1' => gem1, 'gem2' => gem2}
      allow(YARD::GemIndex).to receive(:find_all_by_name) do |k, _ver|
        specs.grep(k).map {|name| specs[name] }
      end
      allow(YARD::GemIndex).to receive(:each) {|&b| specs.values.each(&b) }
      run '-g'
      run '--gems'
    end

    it "accepts -G, --gemfile" do
      bundler_required
      @no_verify_libraries = true
      @options[:single_library] = false

      @libraries['gem1'] = [Server::LibraryVersion.new('gem1', '1.0.0', nil, :gem)]
      @libraries['gem2'] = [Server::LibraryVersion.new('gem2', '1.0.0', nil, :gem)]
      gem1 = double(:gem1, :name => 'gem1', :version => '1.0.0', :full_gem_path => '/path/to/foo')
      gem2 = double(:gem2, :name => 'gem2', :version => '1.0.0', :full_gem_path => '/path/to/bar')
      lockfile_parser = double(:new, :specs => [gem1, gem2])
      allow(Bundler::LockfileParser).to receive(:new).and_return(lockfile_parser)

      expect(File).to receive(:exist?).at_least(2).times.with("Gemfile.lock").and_return(true)
      allow(File).to receive(:read)

      run '-G'
      run '--gemfile'

      expect(File).to receive(:exist?).with("different_name.lock").and_return(true)
      run '--gemfile', 'different_name'
    end

    it "warns if lockfile is not found (with -G)" do
      bundler_required
      expect(File).to receive(:exist?).with(/\.yardopts$/).at_least(:once).and_return(false)
      expect(File).to receive(:exist?).with('somefile.lock').and_return(false)
      expect(log).to receive(:warn).with(/Cannot find somefile.lock/)
      run '-G', 'somefile'
    end

    it "displays an error if Bundler not available (with -G)" do
      expect(@cli).to receive(:require).with('bundler').and_raise(LoadError)
      expect(log).to receive(:error).with(/Bundler not available/)
      run '-G'
    end

    it "loads template paths after adapter template paths" do
      unstub_adapter
      @cli.adapter = Server::WebrickAdapter
      run '-t', 'foo'
      expect(Templates::Engine.template_paths.last).to eq 'foo'
    end

    it "loads ruby code (-e) after adapter" do
      unstub_adapter
      @cli.adapter = Server::WebrickAdapter
      path = File.dirname(__FILE__) + '/tmp.adapterscript.rb'
      begin
        File.open(path, 'w') do |f|
          f.puts "YARD::Templates::Engine.register_template_path 'foo'"
          f.flush
          run '-e', f.path
          expect(Templates::Engine.template_paths.last).to eq 'foo'
        end
      ensure
        File.unlink(path)
      end
    end
  end
end
