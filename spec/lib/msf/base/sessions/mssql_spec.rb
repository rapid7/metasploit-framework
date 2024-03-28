# frozen_string_literal: true

require 'spec_helper'
require 'rex/post/mssql'

RSpec.describe Msf::Sessions::MSSQL do
  let(:client) { instance_double(Rex::Proto::MSSQL::Client) }
  let(:opts) { { client: client } }
  let(:console_class) { Rex::Post::MSSQL::Ui::Console }
  let(:user_input) { instance_double(Rex::Ui::Text::Input::Readline) }
  let(:user_output) { instance_double(Rex::Ui::Text::Output::Stdio) }
  let(:name) { 'mssql' }
  let(:log_source) { "session_#{name}" }
  let(:type) { 'mssql' }
  let(:description) { 'MSSQL' }
  let(:can_cleanup_files) { false }
  let(:address) { '192.0.2.1' }
  let(:port) { 1433 }
  let(:peer_info) { "#{address}:#{port}" }
  let(:console) do
    console = Rex::Post::MSSQL::Ui::Console.new(session)
    console.disable_output = true
    console
  end
  let(:envchange_result) { { type: 1, old: 'master', new: 'master' } }

  before(:each) do
    allow(user_input).to receive(:intrinsic_shell?).and_return(true)
    allow(user_input).to receive(:output=)
    allow(client).to receive(:initial_info_for_envchange).with({ envchange: 1 }).and_return(envchange_result)
    allow(client).to receive(:peerinfo).and_return(peer_info)
    allow(client).to receive(:peerport).and_return(port)
    allow(client).to receive(:peerhost).and_return(address)
  end

  it_behaves_like 'client session'
end
