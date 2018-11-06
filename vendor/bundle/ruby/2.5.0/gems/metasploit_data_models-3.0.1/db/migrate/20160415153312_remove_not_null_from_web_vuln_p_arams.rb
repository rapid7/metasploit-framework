class RemoveNotNullFromWebVulnPArams < ActiveRecord::Migration
  def change
    change_column_null(:web_vulns, :params, true)
  end
end
