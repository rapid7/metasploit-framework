require 'test_helper'

describe 'Joining with an alias' do
  it "Works properly" do
    ChildTag.includes(:parent_tag).references(:parent_tag)
      .where("parent_tags_tags.id" => [2,3,4]).to_sql.must_match /"parent_tags_tags"."id" IN \(2, 3, 4\)/
  end
end
