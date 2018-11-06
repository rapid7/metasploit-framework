require 'test_helper'

describe 'Contains queries' do
  let(:contained_within_regex)        { %r{\"people\"\.\"ip\" << '127.0.0.1/24'} }
  let(:contained_within_equals_regex) { %r{\"people\"\.\"ip\" <<= '127.0.0.1/24'} }
  let(:contains_ip_regex)             { %r{\"people\"\.\"ip\" >> '127.0.0.1'} }
  let(:contains_array_regex)          { %r{\"people\"\.\"tag_ids\" @> '\{1,2\}'} }
  let(:contains_hstore_regex)         { %r{\"people\"\.\"data\" @> '\"nickname\"=>"Dan"'} }
  let(:contained_in_array_regex)      { %r{\"people\"\.\"tag_ids\" <@ '\{1,2\}'} }
  let(:contained_in_hstore_regex)     { %r{\"people\"\.\"data\" <@ '\"nickname\"=>"Dan"'} }
  let(:contains_equals_regex)         { %r{\"people\"\.\"ip\" >>= '127.0.0.1'} }
  let(:equality_regex) { %r{\"people\"\.\"tags\" = '\{"?working"?\}'} }

  describe '.where.contained_within(:column, value)' do
    it 'generates the appropriate where clause' do
      query = Person.where.contained_within(:ip => '127.0.0.1/24')
      query.to_sql.must_match contained_within_regex
    end
  end

  describe '.where.contained_within_or_equals(:column, value)' do
    it 'generates the appropriate where clause' do
      query = Person.where.contained_within_or_equals(:ip => '127.0.0.1/24')
      query.to_sql.must_match contained_within_equals_regex
    end
  end

  describe '.where.contained_within_or_equals(:column, value)' do
    it 'generates the appropriate where clause' do
      query = Person.where.contains_or_equals(:ip => '127.0.0.1')
      query.to_sql.must_match contains_equals_regex
    end
  end

  describe '.where.contains(:column => value)' do
    it 'generates the appropriate where clause for inet columns' do
      query = Person.where.contains(:ip => '127.0.0.1')
      query.to_sql.must_match contains_ip_regex
    end

    it 'generates the appropriate where clause for array columns' do
      query = Person.where.contains(:tag_ids => [1,2])
      query.to_sql.must_match contains_array_regex
    end

    it 'generates the appropriate where clause for hstore columns' do
      query = Person.where.contains(data: { nickname: 'Dan' })
      query.to_sql.must_match contains_hstore_regex
    end

    it 'generates the appropriate where clause for hstore columns on joins' do
      query = Tag.joins(:person).where.contains(people: { data: { nickname: 'Dan' } })
      query.to_sql.must_match contains_hstore_regex
    end

    it 'allows chaining' do
      query = Person.where.contains(:tag_ids => [1,2]).where(:tags => ['working']).to_sql

      query.must_match contains_array_regex
      query.must_match equality_regex
    end

    it 'generates the appropriate where clause for array columns on joins' do
      query = Tag.joins(:person).where.contains(people: { tag_ids: [1,2] }).to_sql

      query.must_match contains_array_regex
    end
  end

  describe '.where.contained_in_array(:column => value)' do
    it 'generates the appropriate where clause for inet columns' do
      query = Person.where.contains(:ip => '127.0.0.1')
      query.to_sql.must_match contains_ip_regex
    end

    it 'generates the appropriate where clause for array columns' do
      query = Person.where.contained_in_array(:tag_ids => [1,2])
      query.to_sql.must_match contained_in_array_regex
    end

    it 'generates the appropriate where clause for hstore columns' do
      query = Person.where.contained_in_array(data: { nickname: 'Dan' })
      query.to_sql.must_match contained_in_hstore_regex
    end

    it 'generates the appropriate where clause for hstore columns on joins' do
      query = Tag.joins(:person).where.contained_in_array(people: { data: { nickname: 'Dan' } })
      query.to_sql.must_match contained_in_hstore_regex
    end

    it 'allows chaining' do
      query = Person.where.contained_in_array(:tag_ids => [1,2]).where(:tags => ['working']).to_sql

      query.must_match contained_in_array_regex
      query.must_match equality_regex
    end

    it 'generates the appropriate where clause for array columns on joins' do
      query = Tag.joins(:person).where.contained_in_array(people: { tag_ids: [1,2] }).to_sql

      query.must_match contained_in_array_regex
    end
  end
end
