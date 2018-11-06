RSpec.shared_examples_for 'MetasploitDataModels::Search::Operation::IPAddress::*.match' do |options={}|
  options.assert_valid_keys(4, 6)

  subject(:match) {
    described_class.match(formatted_value)
  }

  #
  # Shared Examples
  #

  shared_examples_for 'match' do |boolean|
    if boolean
      it { is_expected.to be_a described_class }

      it 'does not set #operator' do
        expect(match.operator).to be_nil
      end

      it 'sets #value' do
        expect(match.value).not_to be_nil
      end
    else
      it { is_expected.to be_nil }
    end
  end

  context 'with IPv4' do
    ipv4 = options.fetch(4, [])
    ipv4 = Set.new Array.wrap(ipv4)

    key_set = Set.new([:cidr, :nmap, :range, :single])

    unless key_set.superset?(ipv4)
      unknown_keys = ipv4 - key_set

      raise ArgumentError, "keys (#{unknown_keys.sort.to_sentence}) not in known keys (#{key_set.sort.to_sentence})"
    end

    context 'with CIDR' do
      let(:formatted_value) {
        '1.2.3.4/24'
      }

      it_should_behave_like 'match', ipv4.include?(:cidr)
    end

    context 'with NMAP' do
      let(:formatted_value) {
        '1-2,4.5,6-7.8-9,10-11.12,13'
      }

      it_should_behave_like 'match', ipv4.include?(:nmap)
    end

    context 'with range' do
      let(:formatted_value) {
        '1.2.3.4-5.6.7.8'
      }

      it_should_behave_like 'match', ipv4.include?(:range)
    end

    context 'with single' do
      let(:formatted_value) {
        '1.2.3.4'
      }

      it_should_behave_like 'match', ipv4.include?(:single)
    end
  end

  context 'with IPv6' do
    ipv6 = options.fetch(6, [])
    ipv6 = Set.new Array.wrap(ipv6)

    key_set = Set.new([:cidr, :range, :single])

    unless key_set.superset?(ipv6)
      unknown_keys = ipv6 - key_set

      raise ArgumentError, "keys (#{unknown_keys.sort.to_sentence}) not in known keys (#{key_set.sort.to_sentence})"
    end

    context 'with CIDR' do
      let(:formatted_value) {
        '1:2:3:4:5:6:7:8/48'
      }

      it_should_behave_like 'match', ipv6.include?(:cidr)
    end

    context 'with range' do
      let(:formatted_value) {
        '1:2:3:4:5:6:7:8-9:10:11:12:13:14:15:16'
      }

      it_should_behave_like 'match', ipv6.include?(:range)
    end

    context 'with single' do
      let(:formatted_value) {
        '1:2:3:4:5:6:7:8'
      }

      it_should_behave_like 'match', ipv6.include?(:single)
    end
  end
end