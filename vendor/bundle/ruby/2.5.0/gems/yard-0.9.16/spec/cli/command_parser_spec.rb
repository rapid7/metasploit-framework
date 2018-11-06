# frozen_string_literal: true

RSpec.describe YARD::CLI::CommandParser do
  describe "#run" do
    before do
      @cmd = CLI::CommandParser.new
    end

    it "shows help if --help is provided" do
      command = double(:command)
      expect(command).to receive(:run).with('--help')
      CLI::CommandParser.commands[:foo] = command
      @cmd.class.default_command = :foo
      @cmd.run(*%w(foo --help))
    end

    it "uses default command if first argument is a switch" do
      command = double(:command)
      expect(command).to receive(:run).with('--a', 'b', 'c')
      CLI::CommandParser.commands[:foo] = command
      @cmd.class.default_command = :foo
      @cmd.run(*%w(--a b c))
    end

    it "uses default command if no arguments are provided" do
      command = double(:command)
      expect(command).to receive(:run)
      CLI::CommandParser.commands[:foo] = command
      @cmd.class.default_command = :foo
      @cmd.run
    end

    it "lists commands if command is not found" do
      expect(@cmd).to receive(:list_commands)
      @cmd.run(*%w(unknown_command --args))
    end

    it "lists commands if --help is provided as sole argument" do
      expect(@cmd).to receive(:list_commands)
      @cmd.run(*%w(--help))
    end
  end
end
