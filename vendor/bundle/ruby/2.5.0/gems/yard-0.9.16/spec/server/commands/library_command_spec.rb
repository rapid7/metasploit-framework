# frozen_string_literal: true
require 'ostruct'

RSpec.describe YARD::Server::Commands::LibraryCommand do
  before do
    allow(Templates::Engine).to receive(:render)
    allow(Templates::Engine).to receive(:generate)
    allow(YARD).to receive(:parse)
    allow(Registry).to receive(:load)
    allow(Registry).to receive(:save)

    @cmd = LibraryCommand.new(:adapter => mock_adapter)
    @request = mock_request("/foo", :xhr? => false)
    @library = OpenStruct.new(:source_path => '.')
    @cmd.library = @library
    allow(@cmd).to receive(:load_yardoc).and_return(nil)
  end

  def call
    expect { @cmd.call(@request) }.to raise_error(NotImplementedError)
  end

  describe "#call" do
    it "raises NotImplementedError" do
      call
    end

    it "sets :rdoc as the default markup in incremental mode" do
      @cmd.incremental = true
      call
      expect(@cmd.options[:markup]).to eq :rdoc
    end

    it "sets :rdoc as the default markup in regular mode" do
      call
      expect(@cmd.options[:markup]).to eq :rdoc
    end
  end
end
