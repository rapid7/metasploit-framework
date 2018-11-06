require 'rails_helper'

<% module_namespacing do -%>
RSpec.describe <%= class_name %>Controller, <%= type_metatag(:controller) %> do

<% for action in actions -%>
  describe "GET #<%= action %>" do
    it "returns http success" do
      get :<%= action %>
      expect(response).to have_http_status(:success)
    end
  end

<% end -%>
end
<% end -%>
