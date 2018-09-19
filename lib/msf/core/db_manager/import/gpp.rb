require 'rex/parser/group_policy_preferences'

module Msf::DBManager::Import::GPP
  def import_gpp_xml(args = {}, &block)
    return unless args && args[:data] && !args[:data].empty?

    gpp = Rex::Parser::GPP.parse(args[:data])

    return unless gpp && gpp.any?

    wspace = find_workspace(args[:workspace])

    return unless wspace && wspace.respond_to?(:id)

    gpp.each do |p|
      # Skip incomplete creds
      next unless p[:USER] && p[:PASS]

      # Store decrypted creds
      create_credential(
        workspace_id: wspace.id,
        origin_type:  :import,
        filename:     args[:filename],
        username:     p[:USER],
        private_data: p[:PASS],
        private_type: :password
      )
    end

    # Store entire file as loot, including metadata
    report_loot(
      workspace: wspace,
      path:      args[:filename],
      name:      File.basename(args[:filename]),
      data:      args[:data],
      type:      'microsoft.windows.gpp',
      ctype:     'text/xml',
      info:      gpp
    )
  end
end
