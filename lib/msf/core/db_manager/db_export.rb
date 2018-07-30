require 'msf/core/db_export'

module Msf::DBManager::DbExport
  def run_db_export(opts)
    exporter = Msf::DBManager::Export.new(framework.db.workspace)

    output_file = exporter.send("to_#{opts[:format]}_file".intern, opts[:path]) do |mtype, mstatus, mname|
      if mtype == :status
        if mstatus == Msf::DBManager::Export::STATUS_START
          ilog "    >> Starting export of #{mname}"
        end
        if mstatus == Msf::DBManager::Export::STATUS_COMPLETE
          ilog "    >> Finished export of #{mname}"
        end
      end
    end

    File.expand_path(output_file)
  end
end
