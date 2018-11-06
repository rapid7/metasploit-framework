# frozen_string_literal: true
def init
  sections :search, [T('../default/layout')]
end

def search
  options.breadcrumb_title = h("Search for '#{@query}'")
  yieldall :contents => erb(:search)
end
