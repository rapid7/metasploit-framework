# frozen_string_literal: true

require 'time'
require 'rex/post/meterpreter/async_window'

RSpec.describe Rex::Post::Meterpreter::AsyncWindow do
  describe '.seconds_until_next_window' do
    # Target-local wall clock — a Time whose #hour and #wday read in the
    # target's local frame. Client#target_time_now produces the same shape:
    # a UTC-flavored Time offset by the target's UTC offset.
    def at(str)
      ::Time.parse("#{str} UTC")
    end

    it 'returns 0 with the default fully-permissive config' do
      # Sat 22:00 — outside any narrow window, but the config is 24/7.
      expect(described_class.seconds_until_next_window(at('2026-08-08 22:00:00'), 0, 24, 0x7F)).to eq(0)
    end

    it 'returns 0 when inside window on a work day' do
      # Wed 10:30 with mon-fri 09-17.
      expect(described_class.seconds_until_next_window(at('2026-08-05 10:30:00'), 9, 17, 0x3E)).to eq(0)
    end

    it 'covers weekend + Monday morning gap from Sat 22:00 with mon-fri 09-17' do
      now = at('2026-08-08 22:00:00') # Sat
      expected = at('2026-08-10 09:00:00') - now
      gap = described_class.seconds_until_next_window(now, 9, 17, 0x3E)
      expect(gap).to be_within(3600).of(expected)
    end

    it 'covers after-hours gap from Fri 17:30 with mon-fri 09-17' do
      now = at('2026-08-07 17:30:00') # Fri
      expected = at('2026-08-10 09:00:00') - now
      gap = described_class.seconds_until_next_window(now, 9, 17, 0x3E)
      expect(gap).to be_within(3600).of(expected)
    end

    it 'covers same-day pre-hours gap' do
      # Wed 07:30 with 09-17 all days → 1.5h.
      gap = described_class.seconds_until_next_window(at('2026-08-05 07:30:00'), 9, 17, 0x7F)
      expect(gap).to be_within(120).of(5400)
    end

    it 'treats a zero work-day mask as all days for target compatibility' do
      gap = described_class.seconds_until_next_window(at('2026-08-05 10:30:00'), 9, 17, 0)
      expect(gap).to eq(0)
    end

    it 'supports overnight windows' do
      expect(described_class.seconds_until_next_window(at('2026-08-05 23:30:00'), 22, 6, 0x7F)).to eq(0)
      expect(described_class.seconds_until_next_window(at('2026-08-05 12:30:00'), 22, 6, 0x7F)).to be_within(1).of(9.5 * 3600)
    end

    it 'assigns the after-midnight portion to the previous work day' do
      monday_only = 0x02
      expect(described_class.seconds_until_next_window(at('2026-08-11 02:00:00'), 22, 6, monday_only)).to eq(0)
      expect(described_class.seconds_until_next_window(at('2026-08-11 22:00:00'), 22, 6, monday_only)).to be > 0
    end

    it 'treats equal start and end as a full-day window on active days' do
      expect(described_class.seconds_until_next_window(at('2026-08-05 12:30:00'), 9, 9, 0x7F)).to eq(0)
    end
  end
end
