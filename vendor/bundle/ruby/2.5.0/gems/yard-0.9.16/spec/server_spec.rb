# frozen_string_literal: true

RSpec.describe YARD::Server do
  describe ".register_static_path" do
    it "registers a static path" do
      YARD::Server.register_static_path 'foo'
      expect(YARD::Server::Commands::StaticFileCommand::STATIC_PATHS.last).to eq "foo"
    end

    it "does not duplicate paths" do
      paths = YARD::Server::Commands::StaticFileCommand::STATIC_PATHS
      count = paths.size
      YARD::Server.register_static_path 'foo2'
      YARD::Server.register_static_path 'foo2'
      expect(paths.size).to eq(count + 1)
      expect(paths.last).to eq 'foo2'
    end
  end
end
