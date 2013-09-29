module Msf::Auxiliary::Report::Get
  def get(suffix)
    method_name = "get_#{suffix}"

    define_method(method_name) do |options={}|
      framework.db.with_connection {
        merged_options = {
            workspace: myworkspace
        }.merge(options)

        framework.db.send(method_name, merged_options)
      }
    end
  end
end