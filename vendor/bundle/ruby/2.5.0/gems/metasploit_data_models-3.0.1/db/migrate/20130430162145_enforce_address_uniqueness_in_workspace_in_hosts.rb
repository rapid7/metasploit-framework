# Changes index on address so it scoped to workspace_id and is unique to match the validation in {Mdm::Host} on
# {Mdm::Host#address}.
class EnforceAddressUniquenessInWorkspaceInHosts < ActiveRecord::Migration
  TABLE_NAME = :hosts

  # maps Table -> Association Column for models that "belong to" a Host
  HOST_ASSOCIATION_MAP = {
    'clients'          => 'host_id',
    'events'           => 'host_id',
    'exploit_attempts' => 'host_id',
    'exploited_hosts'  => 'host_id',
    'host_details'     => 'host_id',
    'hosts_tags'       => 'host_id',
    'loots'            => 'host_id',
    'notes'            => 'host_id',
    'sessions'         => 'host_id',
    'services'         => 'host_id',
    'vulns'            => 'host_id'
  }

  # Historically there a few scenarios where a user could end up with Hosts
  #  in the same workspace with the same IP. Primarily, if you run a Nexpose Scan
  #  and a Discover scan simultaneously, AR does not know about these separate
  #  transactions, so the Hosts will be valid when added and the user will end up
  #  (when transaction completes) with two hosts with the same IP in the same workspace.
  #
  # Since we are adding a DB uniq constraint here, this migration could fail if the user
  #  has hit aforementioned scenarios. So we try to "merge" any hosts with the same
  #  address in the same workspace before adding the DB constraint, to prevent the
  #  migration from simply failing.
  #
  # Note: We can't rely on AR directly here (or in any migration), since we have no
  #  idea what version of the code the user has checked out. So we fall back to SQL :(
  def find_and_merge_duplicate_hosts!
    # find all duplicate addresses within the same workspace currently in the db
    dupe_addresses_and_workspaces = ActiveRecord::Base.connection.execute(%Q{
      SELECT workspace_id, address, count_addr
        FROM (
          SELECT workspace_id, address, COUNT(address) AS count_addr
            FROM hosts
            GROUP BY address, workspace_id
        ) X
        WHERE count_addr > 1
    })

    if dupe_addresses_and_workspaces.present? and
       not dupe_addresses_and_workspaces.num_tuples.zero?
      puts "Duplicate hosts in workspace found. Merging host references."
      # iterate through the duped IPs
      dupe_addresses_and_workspaces.each do |result|
        # so its come to this
        address      = ActiveRecord::Base.connection.quote(result['address'])
        workspace_id = result['workspace_id'].to_i
        # look up the duplicate Host table entries to find all IDs of the duped Hosts
        hosts = ActiveRecord::Base.connection.execute(%Q|
          SELECT id
            FROM hosts
            WHERE address=#{address} AND workspace_id=#{workspace_id}
            ORDER BY id DESC
        |)
        # grab and quote the ID for each result row
        hosts = hosts.map { |h| h["id"].to_i }
        # grab every Host entry besides the first one
        first_host_id = hosts.first
        dupe_host_ids = hosts[1..-1]
        # update associations to these duplicate Hosts
        HOST_ASSOCIATION_MAP.each do |table, column|
          ActiveRecord::Base.connection.execute(%Q|
            UPDATE #{table} SET #{column}=#{first_host_id}
              WHERE #{column} IN (#{dupe_host_ids.join(',')})
          |)
        end
        # destroy the duplicate host rows
        ActiveRecord::Base.connection.execute(%Q|
          DELETE FROM hosts WHERE id IN (#{dupe_host_ids.join(',')})
        |)
      end

      # At this point all duped hosts in the same workspace should be merged.
      # You could end up with duplicate services, but hey its better than just
      #   dropping all data about the old Host.
    end
  end

  # Restores old index on address
  def down
    change_table TABLE_NAME do |t|
      t.remove_index [:workspace_id, :address]
      t.index :address
    end
  end

  # Make index on address scope to workspace_id and be unique
  def up
    find_and_merge_duplicate_hosts!
    change_table TABLE_NAME do |t|
      t.remove_index :address
      t.index [:workspace_id, :address], :unique => true
    end
  end
end
