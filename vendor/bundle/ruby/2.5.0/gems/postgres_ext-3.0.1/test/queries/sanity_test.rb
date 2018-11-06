require 'test_helper'

describe 'Ensure that we don\'t stomp on Active Record\'s queries' do
  describe '.where' do
    it 'generates IN clauses for non array columns' do
      query = Person.where(:id => [1,2,3]).to_sql

      query.must_match /IN \(1, 2, 3\)/
    end

    it 'generates IN clauses for non array columns' do
      query = Person.where(:id => []).to_sql

      query.must_match /WHERE 1=0/
    end
  end

  describe '.where(joins: { column: [] })' do
    it 'generates IN clause for non array columns' do
      query = Person.joins(:hm_tags).where(tags: { id: [1,2,3] }).to_sql
      query.must_match /WHERE "tags"\."id" IN \(1, 2, 3\)/
    end
  end

  describe '#habtm_association_ids=' do
    it 'properly deletes records through HABTM association method' do
      person = Person.create(habtm_tag_ids: [Tag.create.id])
      person.update_attributes(habtm_tag_ids: [])
      person.habtm_tag_ids.must_be_empty
    end
  end

  describe 'Associated record array query' do
    it 'correctly identifies the column on associations with different class names' do
      person = Person.create(:habtm_tag_ids => [Tag.create(categories: ['wicked', 'awesome']).id])
      wicked_people = Person.wicked_people
      wicked_people.must_include(person)
    end
  end
end
