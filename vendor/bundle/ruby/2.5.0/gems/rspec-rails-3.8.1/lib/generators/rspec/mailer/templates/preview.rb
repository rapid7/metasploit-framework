<% module_namespacing do -%>
# Preview all emails at http://localhost:3000/rails/mailers/<%= file_path %>
class <%= class_name %>Preview < ActionMailer::Preview
<% actions.each do |action| -%>

  # Preview this email at http://localhost:3000/rails/mailers/<%= file_path %>/<%= action %>
  def <%= action %>
    <%= class_name %><%= Rails.version.to_f >= 5.0 ? "Mailer" : "" %>.<%= action %>
  end
<% end -%>

end
<% end -%>
