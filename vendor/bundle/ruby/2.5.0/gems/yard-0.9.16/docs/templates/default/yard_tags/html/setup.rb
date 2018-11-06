# frozen_string_literal: true
def init
  sections :list, [T('docstring')]
end

def tag_signature(tag)
  types = tag.types || []
  signature = "<strong>#{tag_link_name(tag)}</strong> "
  sig_tag = tag.object.tag('yard.signature')
  extra = sig_tag.text if sig_tag
  extra ||= case types.first
            when 'with_name'
              "name description"
            when 'with_types'
              "[Types] description"
            when 'with_types_and_name'
              "name [Types] description"
            when 'with_title_and_text'
              "title\ndescription"
            when 'with_types_and_title'
              "[Types] title\ndescription"
            else
              "description"
            end
  signature + h(extra).gsub(/\n/, "<br/>&nbsp;&nbsp;&nbsp;")
end
