require 'msf/core/db_export'

module Msf::DBManager::DbExport
  def run_db_export(path, format)
    exporter = Msf::DBManager::Export.new(framework.db.workspace)

    output_file = exporter.send("to_#{format}_file".intern, path) do |mtype, mstatus, mname|
      if mtype == :status
        if mstatus == "start"
          puts("    >> Starting export of #{mname}")
        end
        if mstatus == "complete"
          puts("    >> Finished export of #{mname}")
        end
      end
    end

    File.expand_path(output_file)
  end
end