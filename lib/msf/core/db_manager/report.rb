module Msf::DBManager::Report
  #
  # Find or create a report matching this type/data
  #
  def find_or_create_report(opts)
    report_report(opts)
  end

  def report_report(opts)
    return if not active
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace = opts.delete(:workspace) || workspace
      path = opts.delete(:path) || (raise RuntimeError, "A report :path is required")

      ret = {}
      user      = opts.delete(:user)
      options   = opts.delete(:options)
      rtype     = opts.delete(:rtype)
      report    = wspace.reports.new
      report.created_by = user
      report.options = options
      report.rtype = rtype
      report.path = path
      msf_import_timestamps(opts,report)
      report.save!

      ret[:task] = report
    }
  end

  #
  # This methods returns a list of all reports in the database
  #
  def reports(wspace=workspace)
    ::ActiveRecord::Base.connection_pool.with_connection {
      wspace.reports
    }
  end
end