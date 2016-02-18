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
end