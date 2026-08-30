# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Sessions::SMB do
  let(:rstream) { instance_double(Rex::Socket) }
  let(:client) { instance_double(RubySMB::Client) }
  let(:dispatcher) { instance_double(RubySMB::Dispatcher::Socket) }
  let(:opts) { { client: client } }
  let(:console_class) { Rex::Post::SMB::Ui::Console }
  let(:user_input) { instance_double(Rex::Ui::Text::Input::Readline) }
  let(:user_output) { instance_double(Rex::Ui::Text::Output::Stdio) }
  let(:name) { 'name' }
  let(:log_source) { "session_#{name}" }
  let(:type) { 'smb' }
  let(:description) { 'SMB' }
  let(:can_cleanup_files) { false }
  let(:address) { '192.0.2.1' }
  let(:port) { 1337 }
  let(:peer_info) { "#{address}:#{port}" }

  before(:each) do
    allow(user_input).to receive(:intrinsic_shell?).and_return(true)
    allow(user_input).to receive(:output=)
    allow(rstream).to receive(:peerinfo).and_return(peer_info)
    allow(client).to receive(:dispatcher).and_return(dispatcher)
    allow(dispatcher).to receive(:tcp_socket).and_return(rstream)
  end

  it_behaves_like 'client session'
end
