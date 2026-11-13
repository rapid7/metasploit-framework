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
    let(:log) { '/var/log/nginx/access.log' }

    before do
      subject.instance_variable_set(:@probe_errors, 0)
      allow(subject).to receive(:file?) { |p| p == log }
    end

    # Default stub: the log is readable (readable_log? probe says "readable")
    # and no IOC grep hits. Per-test overrides compose with this.
    def stub_readable_log_with(&block)
      allow(subject).to receive(:cmd_exec) do |cmd|
        if cmd.start_with?('test -r ')
          'readable'
        else
          block ? block.call(cmd).to_s : ''
        end
      end
    end

    it 'flags an attacker IP when it appears in the client-address field' do
      stub_readable_log_with do |cmd|
        # The grep uses Regexp.escape so the dots in the IP are backslashed.
        '142.93.149.77 - - [22/Sep/2026] "GET /"' if cmd.include?(Regexp.escape('142.93.149.77'))
      end
      expect(subject.check_logs).to include("log:#{log}:142.93.149.77")
    end

    it 'anchors each attacker-IP grep to the client-address field' do
      # Negative test that verifies the grep *pattern* actually anchors, not
      # just that an empty stub returns no result. Captures every cmd and
      # asserts each IP's grep starts at the beginning of the line.
      cmds = []
      allow(subject).to receive(:file?) { |p| p == log }
      allow(subject).to receive(:cmd_exec) do |cmd|
        cmds << cmd
        cmd.start_with?('test -r ') ? 'readable' : ''
      end
      subject.check_logs
      subject.class::IOC_IPS.each do |ip|
        prefix = "grep -E -m1 '^#{Regexp.escape(ip)}[[:space:]]'"
        expect(cmds).to include(a_string_starting_with(prefix))
      end
    end

    it 'flags the attacker-request header in a header-logged position' do
      stub_readable_log_with do |cmd|
        '... "x-vc-opt": "1"' if cmd.include?('grep -E -i -m1')
      end
      expect(subject.check_logs).to include("log:#{log}:header=x-vc-opt")
    end

    it 'does not flag x-vc-opt when it only appears inside a quoted URL path' do
      # The tightened regex must not match a request path like
      # GET /x-vc-opt or ?x-vc-opt=1 inside the "$request" field. Confirm by
      # inspecting the generated grep pattern: it must require a whitespace or
      # quote boundary before the header name and a header-delimiter after.
      cmds = []
      allow(subject).to receive(:file?) { |p| p == log }
      allow(subject).to receive(:cmd_exec) do |cmd|
        cmds << cmd
        cmd.start_with?('test -r ') ? 'readable' : ''
      end
      subject.check_logs
      header_cmds = cmds.grep(/x-vc-opt/)
      expect(header_cmds).not_to be_empty
      header_cmds.each do |cmd|
        expect(cmd).to include('([[:space:]"])x-vc-opt[[:space:]]*[":=]')
      end
    end

    it 'returns nothing when logs contain no attacker IPs or header' do
      stub_readable_log_with
      expect(subject.check_logs).to eq([])
    end

    it 'counts an unreadable log as a probe failure and skips IOC greps' do
      # test -r returns empty when the session user cannot read the log.
      allow(subject).to receive(:cmd_exec).and_return('')
      allow(subject).to receive(:print_warning)
      expect(subject.check_logs).to eq([])
      expect(subject.instance_variable_get(:@probe_errors)).to be >= 1
    end
  end

  describe '#check_hashes' do
    it 'counts a silent nil digest return as a probe failure' do
      # file_remote_digestmd5 on Meterpreter can catch its own exception and
      # return nil without raising. That path must still mark the scan
      # incomplete rather than quietly skip the hash comparison.
      subject.instance_variable_set(:@probe_errors, 0)
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/vc-sysmond' }
      allow(subject).to receive(:file_remote_digestmd5).and_return(nil)
      allow(subject).to receive(:print_warning)
      expect(subject.check_hashes).to eq([])
      expect(subject.instance_variable_get(:@probe_errors)).to be >= 1
    end
  end

  describe '#run' do
    it 'reports no compromise when the host is clean' do
      expect(subject).not_to receive(:report_note)
      subject.run
    end

    it 'does not file a vulnerability record for an IOC match' do
      # IOCs are evidence of past attacker activity, not of CVE-2026-93952
      # vulnerability; the module reports a note and leaves disposition to the
      # operator, so report_vuln must not fire.
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/.vcnode.js' }
      allow(subject).to receive(:session).and_return(double('session', session_host: '192.0.2.10'))
      allow(subject).to receive(:report_note)
      expect(subject).not_to receive(:report_vuln)
      subject.run
    end

    it 'files a note when an indicator is found' do
      allow(subject).to receive(:file?) { |p| p == '/usr/local/sbin/.vcnode.js' }
      allow(subject).to receive(:session).and_return(double('session', session_host: '192.0.2.10'))
      expect(subject).to receive(:report_note).with(hash_including(type: 'velocloud.cve_2026_93952.ioc'))
      subject.run
    end

    it 'warns the operator when probes failed so a clean result is not mistaken for safe' do
      allow(subject).to receive(:file?).and_raise(StandardError, 'session lost')
      allow(subject).to receive(:elog)
      expect(subject).to receive(:print_warning).with(/probe\(s\) failed; this result is incomplete/).at_least(:once)
      # Also warns on each failing probe; use at_least so the implementation can
      # emit either per-probe or summary warnings.
      allow(subject).to receive(:print_warning)
      subject.run
    end
  end
end
