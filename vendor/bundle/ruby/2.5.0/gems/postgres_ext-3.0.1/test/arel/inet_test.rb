require 'test_helper'

describe 'INET related AREL functions' do
  describe 'quoting IPAddr in sql statement' do
    it 'properly converts IPAddr to quoted strings when passed as an argument to a where clause' do
      Person.where(:ip => IPAddr.new('127.0.0.1')).to_sql.must_include("'127.0.0.1/32'")
    end
  end

  describe 'contained with (<<) operator' do
    it 'converts Arel contained_within statements to <<' do
      arel_table = Person.arel_table

      arel_table.where(arel_table[:ip].contained_within(IPAddr.new('127.0.0.1/24'))).to_sql.must_match /<< '127.0.0.0\/24'/
    end
  end

  describe 'contained within or equals (<<=) operator' do
    it 'converts Arel contained_within_or_equals statements to  <<=' do
      arel_table  = Person.arel_table

      arel_table.where(arel_table[:ip].contained_within_or_equals(IPAddr.new('127.0.0.1/24'))).to_sql.must_match /<<= '127.0.0.0\/24'/
    end
  end
  describe 'contains (>>) operator' do
    it 'converts Arel contains statements to >>' do
      arel_table = Person.arel_table

      arel_table.where(arel_table[:ip].contains(IPAddr.new('127.0.0.1/24'))).to_sql.must_match />> '127.0.0.0\/24'/
    end
  end

  describe 'contains or equals (>>=) operator' do
    it 'converts Arel contains_or_equals statements to  >>=' do
      arel_table  = Person.arel_table

      arel_table.where(arel_table[:ip].contains_or_equals(IPAddr.new('127.0.0.1/24'))).to_sql.must_match />>= '127.0.0.0\/24'/
    end
  end
end
