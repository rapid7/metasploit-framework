# frozen_string_literal: true

RSpec.shared_examples 'session compatible client' do
  it { is_expected.to respond_to(:peerhost).with(0).arguments }
  it { is_expected.to respond_to(:peerport).with(0).arguments }
  it { is_expected.to respond_to(:peerinfo).with(0).arguments }

  describe '#peerhost' do
    it 'returns the ip address' do
      expect(subject.peerhost).to eq(host)
    end
  end

  describe '#peerport' do
    it 'returns the port number' do
      expect(subject.peerport).to eq(port)
    end
  end

  describe '#peerinfo' do
    it 'returns the peer info' do
      expect(subject.peerinfo).to eq(info)
    end
  end
end

RSpec.shared_examples 'session compatible SQL client' do
  it_behaves_like 'session compatible client'

  it { is_expected.to respond_to(:current_database).with(0).arguments }

  describe '#current_database' do
    it 'returns the database name' do
      expect(subject.current_database).to eq(db_name)
    end
  end
end
