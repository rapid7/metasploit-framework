# frozen_string_literal: true

require 'spec_helper'
require 'postgres/postgres-pr/connection'

RSpec.describe Msf::Sessions::PostgreSQL do
  let(:client) { instance_double(Msf::Db::PostgresPR::Connection) }
  let(:opts) { { client: client } }
  let(:console_class) { Rex::Post::PostgreSQL::Ui::Console }
  let(:user_input) { instance_double(Rex::Ui::Text::Input::Readline) }
  let(:user_output) { instance_double(Rex::Ui::Text::Output::Stdio) }
  let(:name) { 'postgresql' }
  let(:log_source) { "session_#{name}" }
  let(:type) { 'postgresql' }
  let(:description) { 'PostgreSQL' }
  let(:can_cleanup_files) { false }
  let(:address) { '192.0.2.1' }
  let(:port) { 5432 }
  let(:peer_info) { "#{address}:#{port}" }
  let(:current_database) { 'template1' }

  before(:each) do
    allow(user_input).to receive(:intrinsic_shell?).and_return(true)
    allow(user_input).to receive(:output=)
    allow(client).to receive(:peerinfo).and_return(peer_info)
    allow(client).to receive(:peerhost).and_return(address)
    allow(client).to receive(:peerport).and_return(port)
    allow(client).to receive(:params).and_return({ 'database' => current_database })
    allow(client).to receive(:current_database).and_return(current_database)
  end

  it_behaves_like 'client session'
end
