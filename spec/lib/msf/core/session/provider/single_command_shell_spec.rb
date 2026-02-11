# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Session::Provider::SingleCommandShell do
  class DummySingleCommandShell
    include Msf::Session::Provider::SingleCommandShell

    attr_reader :writes

    def initialize
      @writes = []
    end

    def platform
      'linux'
    end

    def shell_init
      true
    end

    def shell_read(*)
      nil
    end

    def shell_write(buf)
      @writes << buf
    end

    def shell_close
      true
    end

    def shell_read_until_token(_token, _wanted_idx = 0, _timeout = 10)
      ''
    end
  end

  describe '#shell_command_token_base' do
    it 'does not inject a separator after a trailing newline' do
      shell = DummySingleCommandShell.new

      shell.shell_command_token_base("id\n", 1, ';')

      expect(shell.writes.last).not_to match(/\n;/)
    end
  end
end
