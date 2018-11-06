# frozen_string_literal: true
require 'optparse'

RSpec.describe YARD::CLI::Command do
  describe "#parse_options" do
    before do
      @options = OptionParser.new
      @saw_foo = false
      @options.on('--foo') { @saw_foo = true }
    end

    def parse(*args)
      CLI::Command.new.send(:parse_options, @options, args)
      args
    end

    it "skips unrecognized options but continue to next option" do
      expect(log).to receive(:warn).with(/Unrecognized.*--list/)
      expect(log).to receive(:warn).with(/Unrecognized.*--list2/)
      parse('--list', '--list2', '--foo')
      expect(@saw_foo).to be true
    end

    it "skips unrecognized options and any extra non-option arg that follows" do
      expect(log).to receive(:warn).with(/Unrecognized.*--list/)
      parse('--list', 'foo', '--foo')
      expect(@saw_foo).to be true
    end

    it "stops retrying to parse at non-switch argument" do
      expect(log).to receive(:warn).with(/Unrecognized.*--list/)
      args = parse('--list', 'foo', 'foo', 'foo')
      expect(args).to eq %w(foo foo)
    end
  end
end
