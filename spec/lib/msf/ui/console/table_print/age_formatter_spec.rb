require 'spec_helper'

RSpec.describe Msf::Ui::Console::TablePrint::AgeFormatter do
  before(:each) do
    Timecop.freeze(Time.local(2008, 9, 5, 10, 5, 30))
  end

  after(:each) do
    Timecop.return
  end

  describe '#format' do
    context 'when the input is invalid' do
      it { expect(subject.format('not-a-date')).to eq('<invalid>') }
      it { expect(subject.format((Time.now.utc + 5.minutes).iso8601)).to eq('<invalid>') }
    end

    context 'when the input is valid' do
      # seconds
      it { expect(subject.format((Time.now.utc).iso8601)).to eq('0s') }
      it { expect(subject.format((Time.now.utc - 7.seconds).iso8601)).to eq('7s') }
      it { expect(subject.format((Time.now.utc - 119.seconds).iso8601)).to eq('119s') }

      # minutes
      it { expect(subject.format((Time.now.utc - 120.seconds).iso8601)).to eq('2m') }
      it { expect(subject.format((Time.now.utc - 121.seconds).iso8601)).to eq('2m1s') }
      it { expect(subject.format((Time.now.utc - 5.minutes).iso8601)).to eq('5m') }
      it { expect(subject.format((Time.now.utc - 179.minutes).iso8601)).to eq('179m') }
      it { expect(subject.format((Time.now.utc - 179.minutes - 5.seconds).iso8601)).to eq('179m') }

      # hours
      it { expect(subject.format((Time.now.utc - 180.minutes).iso8601)).to eq('3h') }
      it { expect(subject.format((Time.now.utc - 185.minutes).iso8601)).to eq('3h5m') }
      it { expect(subject.format((Time.now.utc - 7.hours - 5.minutes).iso8601)).to eq('7h5m') }
      it { expect(subject.format((Time.now.utc - 8.hours).iso8601)).to eq('8h') }
      it { expect(subject.format((Time.now.utc - 8.hours - 5.minutes).iso8601)).to eq('8h') }
      it { expect(subject.format((Time.now.utc - 30.hours).iso8601)).to eq('30h') }

      # days
      it { expect(subject.format((Time.now.utc - 4.days).iso8601)).to eq('4d') }
      it { expect(subject.format((Time.now.utc - 4.days - 5.hours).iso8601)).to eq('4d5h') }
      it { expect(subject.format((Time.now.utc - 200.days).iso8601)).to eq('200d') }
      it { expect(subject.format((Time.now.utc - 200.days - 5.hours).iso8601)).to eq('200d') }
      it { expect(subject.format((Time.now.utc - 364.days - 5.hours).iso8601)).to eq('364d') }
      it { expect(subject.format((Time.now.utc - 364.days - 5.hours).iso8601)).to eq('364d') }
      it { expect(subject.format((Time.now.utc - 400.days).iso8601)).to eq('400d') }

      # years
      it { expect(subject.format((Time.now.utc - 10.years).iso8601)).to eq('10y') }
    end
  end
end
