# frozen_string_literal: true
def init
  super
  sections.place(:tag_list).after_any(:files)
end

def menu_lists
  super + [{:type => 'tag', :title => 'Tags', :search_title => 'Tag List'}]
end
