require 'msf/core/opt'

RSpec.describe Msf::Opt do
  subject(:opt) { described_class }

  it { is_expected.to respond_to(:CHOST) }
  it { is_expected.to respond_to(:CPORT) }
  it { is_expected.to respond_to(:LHOST) }
  it { is_expected.to respond_to(:LPORT) }
  it { is_expected.to respond_to(:Proxies) }
  it { is_expected.to respond_to(:RHOST) }
  it { is_expected.to respond_to(:RPORT) }

  context 'constants' do
    context 'CHOST' do
      subject { described_class::CHOST }
      it { is_expected.to be_a(Msf::OptAddress) }
    end

    context 'CPORT' do
      subject { described_class::CPORT }
      it { is_expected.to be_a(Msf::OptPort) }
    end

    context 'LHOST' do
      subject { described_class::LHOST }
      it { is_expected.to be_a(Msf::OptAddress) }
    end

    context 'LPORT' do
      subject { described_class::LPORT }
      it { is_expected.to be_a(Msf::OptPort) }
    end

    context 'Proxies' do
      subject { described_class::Proxies }
      it { is_expected.to be_a(Msf::OptString) }
    end

    context 'RHOST' do
      subject { described_class::RHOST }
      it { is_expected.to be_a(Msf::OptAddressRange) }
    end

    context 'RPORT' do
      subject { described_class::RPORT }
      it { is_expected.to be_a(Msf::OptPort) }
    end

  end

  context 'class methods' do
    let(:default) { 'foo' }
    context 'CHOST()' do
      subject { described_class::CHOST(default) }
      it { is_expected.to be_a(Msf::OptAddress) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

    context 'CPORT()' do
      subject { described_class::CPORT(default) }
      it { is_expected.to be_a(Msf::OptPort) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

    context 'LHOST()' do
      subject { described_class::LHOST(default) }
      it { is_expected.to be_a(Msf::OptAddress) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

    context 'LPORT()' do
      subject { described_class::LPORT(default) }
      it { is_expected.to be_a(Msf::OptPort) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

    context 'Proxies()' do
      subject { described_class::Proxies(default) }
      it { is_expected.to be_a(Msf::OptString) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

    context 'RHOST()' do
      subject { described_class::RHOST(default) }
      it { is_expected.to be_a(Msf::OptAddressRange) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

    context 'RPORT()' do
      subject { described_class::RPORT(default) }
      it { is_expected.to be_a(Msf::OptPort) }
      specify 'sets default' do
        expect(subject.default).to eq(default)
      end
    end

  end

end

