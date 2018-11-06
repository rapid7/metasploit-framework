class RemoveDuplicateServices2 < ActiveRecord::Migration
  def change
    select_mgr = Mdm::Service.arel_table.project(
      Mdm::Service[:host_id],
      Mdm::Service[:proto],
      Mdm::Service[:port].count
    ).group(
      'host_id',
      'port',
      'proto'
    ).having(Mdm::Service[:port].count.gt(1))

    Mdm::Service.find_by_sql(select_mgr).each(&:destroy)

    add_index :services, [:host_id, :port, :proto], unique: true
  end
end
