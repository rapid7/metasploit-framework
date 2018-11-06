# frozen_string_literal: true

class MyProcCommand < Base
  def initialize(&block)
    self.class.send(:undef_method, :run)
    self.class.send(:define_method, :run, &block)
  end
end

class MyCacheCommand < Base
  def run; cache 'foo' end
end

RSpec.describe YARD::Server::Commands::Base do
  describe "#cache" do
    before do
      @command = MyCacheCommand.new(:adapter => mock_adapter, :caching => true)
      @command.request = mock_request(nil)
    end

    it "does not cache if caching == false" do
      expect(File).not_to receive(:open)
      @command.caching = false
      @command.run
    end

    it "requires document root to cache" do
      expect(File).not_to receive(:open)
      @command.adapter.document_root = nil
      @command.run
    end

    it "caches to path/to/file.html and create directories" do
      expect(FileUtils).to receive(:mkdir_p).with('/public/path/to')
      expect(File).to receive(:open).with('/public/path/to/file.html', anything)
      @command.request.path_info = '/path/to/file.html'
      @command.run
    end
  end

  describe "#redirect" do
    it "returns a valid redirection" do
      cmd = MyProcCommand.new { redirect '/foo' }
      expect(cmd.call(mock_request('/foo'))).to eq(
        [302, {"Content-Type" => "text/html", "Location" => "/foo"}, [""]]
      )
    end
  end

  describe "#call" do
    it "handles a NotFoundError and use message as body" do
      cmd = MyProcCommand.new { raise NotFoundError, "hello world" }
      s, _, b = *cmd.call(mock_request('/foo'))
      expect(s).to eq 404
      expect(b).to eq ["hello world"]
    end

    it "does not use message as body if not provided in NotFoundError" do
      cmd = MyProcCommand.new { raise NotFoundError }
      s, _, b = *cmd.call(mock_request('/foo'))
      expect(s).to eq 404
      expect(b).to eq ["Not found: /foo"]
    end

    it "handles 404 status code from #run" do
      cmd = MyProcCommand.new { self.status = 404 }
      s, _, b = *cmd.call(mock_request('/foo'))
      expect(s).to eq 404
      expect(b).to eq ["Not found: /foo"]
    end

    it "does not override body if status is 404 and body is defined" do
      cmd = MyProcCommand.new { self.body = "foo"; self.status = 404 }
      s, _, b = *cmd.call(mock_request('/bar'))
      expect(s).to eq 404
      expect(b).to eq ['foo']
    end

    it "handles body as Array" do
      cmd = MyProcCommand.new { self.body = ['a', 'b', 'c'] }
      _, _, b = *cmd.call(mock_request('/foo'))
      expect(b).to eq %w(a b c)
    end

    it "allows headers to be defined" do
      cmd = MyProcCommand.new { headers['Foo'] = 'BAR' }
      _, h, = *cmd.call(mock_request('/foo'))
      expect(h['Foo']).to eq 'BAR'
    end
  end
end
