require 'test_helper'

describe "Join queries" do
  describe ".joins(:parent_tag) with STI" do
    it 'returns a valid sql query' do
      query = ChildTag.joins(:parent_tag).to_sql
      query.must_match("SELECT \"tags\".* FROM \"tags\" INNER JOIN \"tags\" \"parent_tags_tags\" ON \"parent_tags_tags\".\"id\" = \"tags\".\"parent_id\" AND \"parent_tags_tags\".\"type\" IN ('ParentTag') WHERE \"tags\".\"type\" IN ('ChildTag')")
    end
  end
end
