# frozen_string_literal: true

require 'spec_helper'
require 'rex/proto/mysql/client'

RSpec.describe Msf::Sessions::MySQL do
  let(:client) { instance_double(::Rex::Proto::MySQL::Client) }
  let(:opts) { { client: client, platform: Msf::Platform::Linux.realname, arch: ARCH_X86_64 } }
  let(:console_class) { Rex::Post::MySQL::Ui::Console }
  let(:user_input) { instance_double(Rex::Ui::Text::Input::Readline) }
  let(:user_output) { instance_double(Rex::Ui::Text::Output::Stdio) }
  let(:name) { 'mysql' }
  let(:log_source) { "session_#{name}" }
  let(:type) { 'mysql' }
  let(:description) { 'MySQL' }
  let(:can_cleanup_files) { false }
  let(:address) { '192.0.2.1' }
  let(:port) { 3306 }
  let(:peerinfo) { "#{address}:#{port}" }
  let(:current_database) { 'database_name' }

  before(:each) do
    allow(user_input).to receive(:output=)
    allow(user_input).to receive(:intrinsic_shell?).and_return(true)
    allow(client).to receive(:peerinfo).and_return(peerinfo)
    allow(client).to receive(:peerport).and_return(port)
    allow(client).to receive(:peerhost).and_return(address)
    allow(client).to receive(:current_database).and_return(current_database)
    allow(::Rex::Proto::MySQL::Client).to receive(:connect).and_return(client)
  end

  it_behaves_like 'client session'
end
