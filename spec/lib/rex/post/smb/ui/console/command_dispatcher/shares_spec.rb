# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/smb/ui/console'
require 'rex/post/smb/ui/console/command_dispatcher/shares'

RSpec.describe Rex::Post::SMB::Ui::Console::CommandDispatcher::Shares do
  let(:client) { instance_double(RubySMB::Client) }
  let(:session) { Msf::Sessions::SMB.new(nil, { client: client }) }
  let(:console) do
    console = Rex::Post::SMB::Ui::Console.new(session)
    console.disable_output = true
    console
  end

  before(:each) do
    allow(session).to receive(:client).and_return(client)
    allow(session).to receive(:console).and_return(console)
    allow(session).to receive(:name).and_return('test client name')
    allow(session).to receive(:sid).and_return('test client sid')
  end

  subject(:command_dispatcher) { described_class.new(session.console) }

  describe '#as_ntpath' do
    let(:valid_windows_path) { 'some\\path\\that\\is\\valid' }

    [
      'some\\path\\that\\is\\valid',
      'some/path/that/is/valid',
      'some/./path/that/./is/valid',
      'some/extra/../path/that/extra/../is/valid',
      '/some/path/that/is/valid'
    ].each do |path|
      context "when the path is #{path}" do
        it 'formats it as a valid ntpath' do
          formatted_path = subject.send(:as_ntpath, path)
          expect(formatted_path).to eq valid_windows_path
        end
      end
    end
  end
end
