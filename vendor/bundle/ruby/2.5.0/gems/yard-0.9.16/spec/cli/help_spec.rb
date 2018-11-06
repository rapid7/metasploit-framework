# frozen_string_literal: true

RSpec.describe YARD::CLI::Help do
  describe "#run" do
    it "accepts help command" do
      expect(CLI::Yardoc).to receive(:run).with('--help')
      CLI::Help.run('doc')
    end

    it "accepts no arguments (and lists all commands)" do
      expect(CLI::CommandParser).to receive(:run).with('--help')
      CLI::Help.run
    end

    it "shows all commands if command isn't found" do
      expect(CLI::CommandParser).to receive(:run).with('--help')
      help = CLI::Help.new
      expect(log).to receive(:puts).with(/not found/)
      help.run('unknown')
    end
  end
end
