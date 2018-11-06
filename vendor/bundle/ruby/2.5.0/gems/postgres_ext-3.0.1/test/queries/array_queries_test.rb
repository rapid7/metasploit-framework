require 'test_helper'

describe 'Array queries' do
  let(:equality_regex) { %r{\"people\"\.\"tags\" = '\{"?working"?\}'} }
  let(:overlap_regex)  { %r{\"people\"\.\"tag_ids\" && '\{1,2\}'} }
  let(:any_regex)      { %r{2 = ANY\(\"people\"\.\"tag_ids\"\)} }
  let(:all_regex)      { %r{2 = ALL\(\"people\"\.\"tag_ids\"\)} }

  describe '.where(:array_column => [])' do
    it 'returns an array string instead of IN ()' do
      query = Person.where(:tags => ['working']).to_sql
      query.must_match equality_regex
    end
  end

  describe '.where(joins: { array_column: [] })' do
    it 'returns an array string instead of IN ()' do
      query = Person.joins(:hm_tags).where(tags: { categories: ['working'] }).to_sql
      query.must_match %r{\"tags\"\.\"categories\" = '\{"?working"?\}'}
    end
  end

  describe '.where.overlap(:column => value)' do
    it 'generates the appropriate where clause' do
      query = Person.where.overlap(:tag_ids => [1,2])
      query.to_sql.must_match overlap_regex
    end

    it 'allows chaining' do
      query = Person.where.overlap(:tag_ids => [1,2]).where(:tags => ['working']).to_sql

      query.must_match overlap_regex
      query.must_match equality_regex
    end

    it 'works on joins' do
      query = Person.joins(:hm_tags).where.overlap(tags: { categories: ['working'] }).to_sql
      query.must_match %r{\"tags\"\.\"categories\" && '\{"?working"?\}'}
    end
  end


  describe '.where.any(:column => value)' do
    it 'generates the appropriate where clause' do
      query = Person.where.any(:tag_ids => 2)
      query.to_sql.must_match any_regex
    end

    it 'allows chaining' do
      query = Person.where.any(:tag_ids => 2).where(:tags => ['working']).to_sql

      query.must_match any_regex
      query.must_match equality_regex
    end
  end

  describe '.where.all(:column => value)' do
    it 'generates the appropriate where clause' do
      query = Person.where.all(:tag_ids => 2)
      query.to_sql.must_match all_regex
    end

    it 'allows chaining' do
      query = Person.where.all(:tag_ids => 2).where(:tags => ['working']).to_sql

      query.must_match all_regex
      query.must_match equality_regex
    end
  end
end
