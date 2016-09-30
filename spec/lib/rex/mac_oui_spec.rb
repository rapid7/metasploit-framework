# -*- coding:binary -*-
require 'spec_helper'

require 'rex/mac_oui'

RSpec.describe Rex::Oui do
  describe ".lookup_oui_fullname" do
    subject(:oui_fullname) { described_class.lookup_oui_fullname(mac) }

    context "when valid mac for OUI with name" do
      let(:mac) { '000011' }
      let(:name) { 'Tektrnix' }
      it { is_expected.to eq(name) }
    end

    context "when valid mac for OUI with name and long name" do
      let(:mac) { '00:00:0E:12:34:56' }
      let(:name) { 'Fujitsu' }
      let(:long_name) { 'FUJITSU LIMITED' }
      it { is_expected.to eq("#{name} / #{long_name}") }
    end

    context "when valid mac format, without OUI" do
      let(:mac) { '11:22:33:44:55:66'}
      it { is_expected.to eq('UNKNOWN') }
    end

    context "when invalid mac format" do
      let(:mac) { 'invalid' }
      it "raises an error" do
        expect { oui_fullname }.to raise_error(RuntimeError)
      end
    end
  end

  describe ".lookup_oui_company_name" do
    subject(:oui_company_name) { described_class.lookup_oui_company_name(mac) }

    context "when valid mac for OUI with name" do
      let(:mac) { '000011' }
      let(:name) { 'Tektrnix' }
      it { is_expected.to eq(name) }
    end

    context "when valid mac for OUI with name and long name" do
      let(:mac) { '00:00:0E:12:34:56' }
      let(:name) { 'Fujitsu' }
      let(:long_name) { 'FUJITSU LIMITED' }
      it { is_expected.to eq(long_name) }
    end

    context "when valid mac format, without OUI" do
      let(:mac) { '11:22:33:44:55:66'}
      it { is_expected.to eq('UNKNOWN') }
    end

    context "when invalid mac format" do
      let(:mac) { 'invalid' }
      it "raises an error" do
        expect { oui_company_name }.to raise_error(RuntimeError)
      end
    end
  end

  describe ".check_mac" do
    context "when valid mac" do
      it { expect(described_class.check_mac('AA:BB:CC')).to be_nil }
      it { expect(described_class.check_mac('AABBCC')).to be_nil }
      it { expect(described_class.check_mac('AA:BB:CC:DD')).to be_nil }
      it { expect(described_class.check_mac('AABBCCDD')).to be_nil }
      it { expect(described_class.check_mac('AA:BB:CC:DD:EE')).to be_nil }
      it { expect(described_class.check_mac('AABBCCDDEE')).to be_nil }
      it { expect(described_class.check_mac('AA:BB:CC:DD:EE:FF')).to be_nil }
      it { expect(described_class.check_mac('AABBCCDDEEFF')).to be_nil }
    end

    context "when invalid mac" do
      it { expect { described_class.check_mac('AA') }.to raise_error(RuntimeError) }
      it { expect { described_class.check_mac('AA:BB:CC:DD:JJ') }.to raise_error(RuntimeError) }
      it { expect { described_class.check_mac('AA:BB') }.to raise_error(RuntimeError) }
      it { expect { described_class.check_mac('AABB') }.to raise_error(RuntimeError) }
      it { expect { described_class.check_mac('AA:BB:CC:DD:EE:FF:AA') }.to raise_error(RuntimeError) }
      it { expect { described_class.check_mac('AABBCCDDEEFFAA') }.to raise_error(RuntimeError) }
    end
  end
end
