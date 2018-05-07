# -*- coding:binary -*-
require 'spec_helper'

require 'rex/time'

RSpec.describe Rex::ExtTime do

  let(:conversions) do
    {
      0 => '0 secs',
      1 => '1 sec',
      60 => '1 min',
      61 => '1 min 1 sec',
      121 => '2 mins 1 sec',
      3600 => '1 hour',
      3660 => '1 hour 1 min',
      3661 => '1 hour 1 min 1 sec',
      7326 => '2 hours 2 mins 6 secs',
      86400 => '1 day',
      86401 => '1 day 1 sec',
      86460 => '1 day 1 min',
      86461 => '1 day 1 min 1 sec',
      90000 => '1 day 1 hour',
      90060 => '1 day 1 hour 1 min',
      90125 => '1 day 1 hour 2 mins 5 secs',
      31536000 => '1 year',
      31536003 => '1 year 3 secs',
      31536063 => '1 year 1 min 3 secs',
      31539600 => '1 year 1 hour',
      31622400 => '1 year 1 day',
      31626000 => '1 year 1 day 1 hour',
      31626001 => '1 year 1 day 1 hour 1 sec',
      31626060 => '1 year 1 day 1 hour 1 min',
      31626061 => '1 year 1 day 1 hour 1 min 1 sec'
    }
  end

  subject { described_class }

  describe ".sec_to_s" do
    it "returns string encoded seconds" do
      conversions.each do |k, v|
        expect(subject.sec_to_s(k)).to eq(v)
      end
    end
  end
end
