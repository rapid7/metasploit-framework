# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/meterpreter/ui/console/command_dispatcher/core'

RSpec.describe Rex::Post::Meterpreter::Ui::Console::CommandDispatcher::Core do
  let(:session) { instance_double(Msf::Sessions::Meterpreter) }
  # A meterpreter session *is* a client but for the smb session it *has* a (ruby smb) client
  let(:client) { session }
  let(:console) do
    console = Rex::Post::Meterpreter::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  describe '#parse_work_days' do
    it 'parses hexadecimal masks in base 16' do
      expect(command_dispatcher.parse_work_days('0x3e')).to eq(62)
    end

    it 'accepts an uppercase hexadecimal prefix and digits' do
      expect(command_dispatcher.parse_work_days('0X3E')).to eq(62)
    end

    it 'parses decimal masks in base 10' do
      expect(command_dispatcher.parse_work_days('62')).to eq(62)
    end

    it 'keeps decimal masks with leading zeros in base 10' do
      expect(command_dispatcher.parse_work_days('062')).to eq(62)
    end
  end

  it_behaves_like 'session command dispatcher'
end
