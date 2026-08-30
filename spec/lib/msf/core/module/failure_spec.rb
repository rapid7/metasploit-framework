require 'spec_helper'

RSpec.describe Msf::Module::Failure do
  context 'CONSTANTS' do
    context 'None' do
      subject(:none) {
        described_class::None
      }
      it { is_expected.to eq('none') }
    end

    context 'Unknown' do
      subject(:unknown) {
        described_class::Unknown
      }
      it { is_expected.to eq('unknown') }
    end
    context 'Unreachable' do
      subject(:unreachable) {
        described_class::Unreachable
      }
      it { is_expected.to eq('unreachable') }
    end

    context 'BadConfig' do
      subject(:bad_config) {
        described_class::BadConfig
      }
      it { is_expected.to eq('bad-config') }
    end

    context 'Disconnected' do
      subject(:disconnected) {
        described_class::Disconnected
      }
      it { is_expected.to eq('disconnected') }
    end

    context 'NotFound' do
      subject(:not_found) {
        described_class::NotFound
      }
      it { is_expected.to eq('not-found') }
    end

    context 'UnexpectedReply' do
      subject(:unexpected_reply) {
        described_class::UnexpectedReply
      }

      it { is_expected.to eq('unexpected-reply') }
    end

    context 'TimeoutExpired' do
      subject(:timeout_expired) {
        described_class::TimeoutExpired
      }

      it { is_expected.to eq('timeout-expired') }
    end

    context 'UserInterrupt' do
      subject(:user_interrupt) {
        described_class::UserInterrupt
      }

      it { is_expected.to eq('user-interrupt') }
    end

    context 'NoAccess' do
      subject(:no_access) {
        described_class::NoAccess
      }

      it { is_expected.to eq('no-access') }
    end

    context 'NoTarget' do
      subject(:no_target) {
        described_class::NoTarget
      }

      it { is_expected.to eq('no-target') }
    end

    context 'NotVulnerable' do
      subject(:not_vulnerable) {
        described_class::NotVulnerable
      }

      it { is_expected.to eq('not-vulnerable') }
    end

    context 'PayloadFailed' do
      subject(:payload_failed) {
        described_class::PayloadFailed
      }

      it { is_expected.to eq('payload-failed') }
    end
  end

  describe '.fail_reason_from_check_code' do
    {
      Msf::Exploit::CheckCode::Vulnerable => Msf::Module::Failure::None,
      Msf::Exploit::CheckCode::Appears => Msf::Module::Failure::None,
      Msf::Exploit::CheckCode::Safe => Msf::Module::Failure::NotVulnerable,
      Msf::Exploit::CheckCode::Detected => Msf::Module::Failure::Unknown,
      Msf::Exploit::CheckCode::Unknown => Msf::Module::Failure::Unknown
    }.each do |check_code, expected_reason|
      it "maps #{check_code.code} to #{expected_reason}" do
        expect(described_class.fail_reason_from_check_code(check_code)).to eq(expected_reason)
      end
    end

    it 'returns nil for nil input' do
      expect(described_class.fail_reason_from_check_code(nil)).to be_nil
    end

    context 'with check codes carrying reason metadata' do
      {
        Msf::Exploit::CheckCode::Vulnerable('ThinkPHP 5.0.23 is a vulnerable version.') => Msf::Module::Failure::None,
        Msf::Exploit::CheckCode::Appears('Version 5.0.23 appears vulnerable') => Msf::Module::Failure::None,
        Msf::Exploit::CheckCode::Safe('Patched version detected') => Msf::Module::Failure::NotVulnerable,
        Msf::Exploit::CheckCode::Detected('Service is running') => Msf::Module::Failure::Unknown,
        Msf::Exploit::CheckCode::Unknown('Could not determine') => Msf::Module::Failure::Unknown
      }.each do |check_code, expected_reason|
        it "maps #{check_code.code} with reason '#{check_code.reason}' to #{expected_reason}" do
          expect(described_class.fail_reason_from_check_code(check_code)).to eq(expected_reason)
        end
      end
    end
  end

  describe 'CheckCode equality with metadata (used by report_failure)' do
    let(:vuln_codes) { [Msf::Exploit::CheckCode::Vulnerable, Msf::Exploit::CheckCode::Appears] }

    it 'matches Vulnerable instance with reason via include?' do
      code = Msf::Exploit::CheckCode::Vulnerable('ThinkPHP 5.0.23 is vulnerable')
      expect(vuln_codes.include?(code)).to be true
    end

    it 'matches Appears instance with reason via include?' do
      code = Msf::Exploit::CheckCode::Appears('Version appears vulnerable')
      expect(vuln_codes.include?(code)).to be true
    end

    it 'does not match Safe instance via include?' do
      code = Msf::Exploit::CheckCode::Safe('Patched')
      expect(vuln_codes.include?(code)).to be false
    end

    it 'does not match Detected instance via include?' do
      code = Msf::Exploit::CheckCode::Detected('Service running')
      expect(vuln_codes.include?(code)).to be false
    end
  end
end
