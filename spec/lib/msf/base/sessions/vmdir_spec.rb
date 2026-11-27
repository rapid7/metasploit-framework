require 'spec_helper'
require 'msf/core/exploit/remote/vmdir'
require 'msf/base/sessions/vmdir'

RSpec.describe Msf::Sessions::Vmdir do
  let(:socket) { double('RPC socket', peerinfo: '192.0.2.1:2012', close: nil) }
  let(:client) { instance_double(Msf::Exploit::Remote::Vmdir::Client, socket: socket) }
  let(:key) { 'K' * 20 }
  let(:output) { Rex::Ui::Text::Output::Buffer.new }
  subject(:session) { described_class.new(client, username: 'administrator@vsphere.local', key: key) }

  before do
    session.sid = 7
    session.username = 'operator'
    session.init_ui(nil, output)
  end

  it 'identifies itself as an RPC session rather than an OS shell' do
    expect(session.type).to eq('vmdir')
  end

  it 'supports the Framework session table without modifying its session type' do
    allow(session).to receive(:tunnel_to_s).and_return('192.0.2.2:12345 -> 192.0.2.1:2012')
    row = Msf::Serializer::ReadableText.create_msf_session_row(session, false)
    expect(row[2]).to start_with('vmdir')
    expect(session.type).to eq('vmdir')
  end

  it 'executes a protected read through the retained authenticated client' do
    expect(client).to receive(:directory_state).with('administrator@vsphere.local', key).and_return(3)
    session.console.run_single('state')
    expect(output.dump_buffer).to include('Directory state: 3')
  end

  it 'shows the principal whose server proof was verified' do
    session.console.run_single('whoami')
    expect(output.dump_buffer).to include('Authenticated SSO principal: administrator@vsphere.local')
  end

  it 'backgrounds without closing the RPC association or stopping its console' do
    session.interacting = true
    expect(socket).not_to receive(:close)
    session.console.run_single('background')
    expect(session.interacting).to be(false)
    expect(session.console.stopped?).to be_falsey
  end

  it 'supports the shared help and exit commands' do
    session.console.run_single('help')
    expect(output.dump_buffer).to include('state', 'whoami', 'background')
    session.console.run_single('exit')
    expect(session.console.stopped?).to be(true)
  end

  it 'closes the owned RPC socket during standard session cleanup' do
    expect(socket).to receive(:close)
    session.cleanup
  end

  it 'ends interaction after a protected RPC fails' do
    allow(client).to receive(:directory_state).and_raise(Msf::Exploit::Remote::Vmdir::Error, 'Invalid response MAC')
    session.console.run_single('state')
    expect(output.dump_buffer).to include('Directory-state RPC failed: Invalid response MAC')
    expect(session.console.stopped?).to be(true)
  end
end

RSpec.describe Msf::Sessions::Vmdir::Shell do
  let(:socket) { double('SSH stream socket', close: nil, peerinfo: '192.0.2.1:22') }
  let(:stream) { double('Framework SSH stream', lsock: socket, cleanup: nil) }
  subject(:session) { described_class.new(stream) }

  before do
    allow(stream).to receive(:session=)
    allow(stream).to receive(:logger=)
  end

  it 'closes the SSH stream before restoring appliance state and only cleans up once' do
    callback = double('appliance API cleanup')
    session.after_close = callback
    expect(stream).to receive(:logger=).with(nil).once.ordered
    expect(stream).to receive(:cleanup).once.ordered
    expect(callback).to receive(:call).once.ordered
    session.cleanup
    session.cleanup
  end

  it 'still restores appliance state if the SSH stream is already closed' do
    allow(stream).to receive(:cleanup).and_raise(IOError, 'Closed transport')
    callback = double('appliance API cleanup')
    session.after_close = callback
    expect(callback).to receive(:call)
    session.cleanup
  end
end
