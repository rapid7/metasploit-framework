require 'rails_helper'

<% module_namespacing do -%>
RSpec.describe <%= class_name %>, <%= type_metatag(:model) %> do
  pending "add some examples to (or delete) #{__FILE__}"
end
<% end -%>
