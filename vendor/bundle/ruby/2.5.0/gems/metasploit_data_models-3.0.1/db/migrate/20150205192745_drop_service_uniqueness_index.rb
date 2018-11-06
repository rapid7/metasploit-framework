class DropServiceUniquenessIndex < ActiveRecord::Migration
  def change
    remove_index(:services, :host_id_and_port_and_proto)
  end
end
