# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'post/linux/gather/velocloud_cve_2026_93952_ioc_check' do
  include_context 'Msf::Simple::Framework#modules loading'

  subject do
    mod = load_and_create_module(
      module_type: 'post',
      reference_name: 'linux/gather/velocloud_cve_2026_93952_ioc_check'
    )
    mod.datastore['SESSION'] = 1
    mod
  end

  let(:known_bad_md5) { 'dc78e206eaeadec59fc5801fe4556bd0' }

  before do
    # Default: nothing present, no hashes, empty log scans.
    allow(subject).to receive(:file?).and_return(false)
    allow(subject).to receive(:file_remote_digestmd5).and_return(nil)
    allow(subject).to receive(:cmd_exec).and_return('')
  end

  describe '#check_files' do
    it 'flags a malicious file that exists' do
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/.vcnode.js' }
      expect(subject.check_files).to eq(['file:/usr/local/sbin/.vcnode.js'])
    end

    it 'returns nothing when no malicious files are present' do
      expect(subject.check_files).to eq([])
    end
  end

  describe '#check_hashes' do
    it 'flags the implant when its MD5 matches the published hash' do
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/vc-sysmond' }
      allow(subject).to receive(:file_remote_digestmd5).and_return(known_bad_md5)
      expect(subject.check_hashes).to eq(["hash:/usr/local/sbin/vc-sysmond=#{known_bad_md5}"])
    end

    it 'does not flag a same-named file whose MD5 differs' do
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/vc-sysmond' }
      allow(subject).to receive(:file_remote_digestmd5).and_return('0' * 32)
      expect(subject.check_hashes).to eq([])
    end

    it 'ignores the hash check when the file is absent' do
      expect(subject.check_hashes).to eq([])
    end
  end

  describe '#check_service' do
    it 'flags the malicious systemd unit when present' do
      allow(subject).to receive(:file?) { |p| p == '/etc/systemd/system/vc-sysmon.service' }
      expect(subject.check_service).to eq(['service:/etc/systemd/system/vc-sysmon.service'])
    end
  end

  describe '#check_logs' do
    it 'flags an attacker IP found in an nginx access log' do
      allow(subject).to receive(:file?) { |p| p == '/var/log/nginx/access.log' }
      allow(subject).to receive(:cmd_exec) do |cmd|
        cmd.include?('142.93.149.77') ? '142.93.149.77 - - [22/Sep/2026] "GET /"' : ''
      end
      expect(subject.check_logs).to include('log:/var/log/nginx/access.log:142.93.149.77')
    end

    it 'returns nothing when logs contain no attacker IPs' do
      allow(subject).to receive(:file?) { |p| p == '/var/log/nginx/access.log' }
      expect(subject.check_logs).to eq([])
    end
  end

  describe '#run' do
    it 'reports no compromise and files no vuln when the host is clean' do
      expect(subject).not_to receive(:report_vuln)
      subject.run
    end

    it 'files a vuln when an indicator is found' do
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/.vcnode.js' }
      allow(subject).to receive(:session).and_return(double('session', session_host: '192.0.2.10'))
      allow(subject).to receive(:report_note)
      expect(subject).to receive(:report_vuln).with(hash_including(name: subject.name))
      subject.run
    end
  end
end
