require 'test_helper'

describe 'Array Column Predicates' do
  let(:arel_table) { Person.arel_table }
  describe 'Array Any' do
    context 'string value' do
      it 'creates any predicates' do
        arel_table.where(arel_table[:tags].any('tag')).to_sql.must_match /'tag' = ANY\("people"\."tags"\)/
      end
    end

    context 'integer value' do
      it 'creates any predicates' do
        arel_table.where(arel_table[:tag_ids].any(1)).to_sql.must_match /1 = ANY\("people"\."tag_ids"\)/
      end
    end
  end

  describe 'Array All' do
    context 'string value' do
      it 'creates all predicates' do
        arel_table.where(arel_table[:tags].all('tag')).to_sql.must_match /'tag' = ALL\("people"\."tags"\)/
      end
    end

    context 'integer value' do
      it 'creates all predicates' do
        arel_table.where(arel_table[:tag_ids].all(1)).to_sql.must_match /1 = ALL\("people"\."tag_ids"\)/
      end
    end
  end

  describe 'Array Overlap' do
    it 'converts Arel overlap statement' do
      arel_table.where(arel_table[:tags].overlap(['tag','tag 2'])).to_sql.must_match /&& '\{"?tag"?,"tag 2"\}'/
    end

    it 'converts Arel overlap statement' do
      arel_table.where(arel_table[:tag_ids].overlap([1,2])).to_sql.must_match /&& '\{1,2\}'/
    end

    it 'works with count (and other predicates)' do
      Person.where(arel_table[:tag_ids].overlap([1,2])).count.must_equal 0
    end

    it 'returns matched records' do
      one = Person.create!(:tags => ['one'])
      two = Person.create!(:tags => ['two'])

      query = arel_table.where(arel_table[:tags].overlap(['one'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include(one)

      query = arel_table.where(arel_table[:tags].overlap(['two'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include(two)

      query = arel_table.where(arel_table[:tags].overlap(['two','one'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include(two)
      Person.find_by_sql(query.to_sql).must_include(one)
    end
  end

  describe 'Array Contains' do
    it 'converts Arel contains statement and escapes strings' do
      arel_table.where(arel_table[:tags].contains(['tag','tag 2'])).to_sql.must_match /@> '\{"?tag"?,"tag 2"\}'/
    end

    it 'converts Arel contains statement with numbers' do
      arel_table.where(arel_table[:tag_ids].contains([1,2])).to_sql.must_match /@> '\{1,2\}'/
    end

    it 'works with count (and other predicates)' do
      Person.where(arel_table[:tag_ids].contains([1,2])).count.must_equal 0
    end

    it 'returns matched records' do
      one = Person.create!(:tags => ['one', 'two', 'three'])
      two = Person.create!(:tags => ['one', 'three'])

      query = arel_table.where(arel_table[:tags].contains(['one', 'two'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include one
      Person.find_by_sql(query.to_sql).wont_include two

      query = arel_table.where(arel_table[:tags].contains(['one', 'three'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include one
      Person.find_by_sql(query.to_sql).must_include two

      query = arel_table.where(arel_table[:tags].contains(['two'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include one
      Person.find_by_sql(query.to_sql).wont_include two
    end
  end

  describe 'Array Contained In Array' do
    it 'converts Arel contained_in_array statement and escapes strings' do
      arel_table.where(arel_table[:tags].contained_in_array(['tag','tag 2'])).to_sql.must_match /<@ '\{"?tag"?,"tag 2"\}'/
    end

    it 'converts Arel contained_in_array statement with numbers' do
      arel_table.where(arel_table[:tag_ids].contained_in_array([1,2])).to_sql.must_match /<@ '\{1,2\}'/
    end

    it 'works with count (and other predicates)' do
      Person.where(arel_table[:tag_ids].contained_in_array([1,2])).count.must_equal 0
    end

    it 'returns matched records' do
      one = Person.create!(:tags => ['one', 'two'])
      two = Person.create!(:tags => ['one', 'three'])

      query = arel_table.where(arel_table[:tags].contained_in_array(['one', 'two', 'three'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).must_include one
      Person.find_by_sql(query.to_sql).must_include two

      query = arel_table.where(arel_table[:tags].contained_in_array(['one', 'three'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).wont_include one
      Person.find_by_sql(query.to_sql).must_include two

      query = arel_table.where(arel_table[:tags].contained_in_array(['two'])).project(Arel.sql('*'))
      Person.find_by_sql(query.to_sql).wont_include one
      Person.find_by_sql(query.to_sql).wont_include two
    end
  end
end
