require 'date'

RSpec.describe RubySMB::Field::FileTime do
  subject(:file_time) { described_class.read(binary_filetime) }

  let(:binary_filetime) { "\x36\x32\xe8\xe0\xd2\xe4\xd0\x01" }
  let(:int_filetime) { binary_filetime.unpack('Q<').first }
  let(:str_filetime) { '2015-09-01T11:25:56-05:00' }
  let(:time_filetime) { Time.parse str_filetime }
  let(:datetime_filetime) { time_filetime.to_datetime }

  it { is_expected.to respond_to :val }
  it { is_expected.to respond_to :get }
  it { is_expected.to respond_to :set }
  it { is_expected.to respond_to :to_time }
  it { is_expected.to respond_to :to_datetime }

  describe '#val' do
    it 'should b an Unsigned 64-bit Integer' do
      expect(file_time.val).to be_a BinData::Uint64le
    end
  end

  describe '#get' do
    it 'returns the expected integer value' do
      expect(file_time.val).to eq int_filetime
    end
  end

  describe '#to_time' do
    it 'returns a Time object representing the correct time' do
      expect(file_time.to_time).to eq time_filetime
    end
  end

  describe '#to_datetime' do
    it 'returns a DateTime object representing the correct time' do
      expect(file_time.to_datetime).to eq datetime_filetime
    end
  end

  describe '#set' do
    subject(:empty_filetime) { described_class.new }
    it 'will take a Time object correctly but lose Nanoseconds' do
      empty_filetime.set time_filetime
      val = empty_filetime.get
      expect(val / 10_000_000).to eq(int_filetime / 10_000_000)
    end

    it 'will take a DateTime object correctly but lose Nanoseconds' do
      empty_filetime.set datetime_filetime
      val = empty_filetime.get
      expect(val / 10_000_000).to eq(int_filetime / 10_000_000)
    end

    it 'will accept a raw integer value and set it' do
      empty_filetime.set int_filetime
      expect(empty_filetime.get).to eq int_filetime
    end
  end
end
