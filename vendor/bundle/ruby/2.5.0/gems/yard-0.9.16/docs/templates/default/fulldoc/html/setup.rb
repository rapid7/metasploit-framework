# frozen_string_literal: true
def generate_tag_list
  @list_title = "Tag List"
  @list_type = "tag"
  asset('tag_list.html', erb(:full_list))
end
