# frozen_string_literal: true

require 'spec_helper'

RSpec.describe Msf::Sessions::LDAP do
  let(:client) { instance_double(Rex::Proto::LDAP::Client) }
  let(:opts) { { client: client } }
  let(:console_class) { Rex::Post::LDAP::Ui::Console }
  let(:user_input) { instance_double(Rex::Ui::Text::Input::Readline) }
  let(:user_output) { instance_double(Rex::Ui::Text::Output::Stdio) }
  let(:name) { 'name' }
  let(:log_source) { "session_#{name}" }
  let(:type) { 'ldap' }
  let(:description) { 'LDAP' }
  let(:can_cleanup_files) { false }
  let(:address) { '192.0.2.1' }
  let(:port) { 1337 }
  let(:peer_info) { "#{address}:#{port}" }

  before(:each) do
    allow(user_input).to receive(:intrinsic_shell?).and_return(true)
    allow(user_input).to receive(:output=)
    allow(client).to receive(:peerinfo).and_return(peer_info)
    allow(client).to receive(:peerhost).and_return(address)
    allow(client).to receive(:peerport).and_return(port)
  end

  it_behaves_like 'client session'
end
