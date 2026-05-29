require 'rspec'
require 'stringio'

RSpec.describe 'IPMI Dump Hashes Scanner' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    load_and_create_module(
      module_type: 'auxiliary',
      reference_name: 'scanner/ipmi/ipmi_dumphashes'
    )
  end

  let(:udp_sock) do
    instance_double(Rex::Socket::Udp)
  end

  before do
    subject.datastore['USER_FILE'] = 'users.txt'
    subject.datastore['PASS_FILE'] = 'passwords.txt'
    subject.datastore['CRACK_COMMON'] = false
    subject.datastore['SESSION_MAX_ATTEMPTS'] = 1
    subject.datastore['SESSION_RETRY_DELAY'] = 0
    subject.datastore['RHOST'] = '192.0.2.1'
    subject.datastore['RPORT'] = 623

    allow(File).to receive(:open).with('users.txt', 'rb').and_yield(StringIO.new("admin\nroot\n"))
    allow(File).to receive(:open).with('passwords.txt', 'rb').and_yield(StringIO.new("password\n"))
    allow(Rex::Socket::Udp).to receive(:create).and_return(udp_sock)
    allow(subject).to receive(:add_socket)
    allow(subject).to receive(:ipmi_status)
    allow(subject).to receive(:ipmi_error)
    allow(subject).to receive(:ipmi_good)
    allow(subject).to receive(:report_hash).and_return(1)
    allow(subject).to receive(:report_vuln)
    allow(subject).to receive(:report_cracked_cred)
    allow(subject).to receive(:write_output_files)
    allow(subject).to receive(:sleep)
    allow(Rex).to receive(:sleep)
  end

  describe '#run_host' do
    it 'stops username enumeration when the host never answers the first open-session probe' do
      allow(udp_sock).to receive(:sendto)
      allow(udp_sock).to receive(:recvfrom).and_return([nil, nil, nil])

      expect(udp_sock).to receive(:sendto).exactly(3).times

      subject.run_host('192.0.2.1')
    end
  end
end
