module Msf::DBManager::Report
  # TODO This method does not attempt to find. It just creates
  # a report based on the passed params.
  def find_or_create_report(opts)
    report_report(opts)
  end

  # Creates a Report based on passed parameters. Does not handle
  # child artifacts.
  # @param opts [Hash]
  # @return [Integer] ID of created report
  def report_report(opts)
    return if not active
    created = opts.delete(:created_at)
    updated = opts.delete(:updated_at)
    state   = opts.delete(:state)

  ::ActiveRecord::Base.connection_pool.with_connection {
    report = Report.new(opts)
    report.created_at = created
    report.updated_at = updated

    unless report.valid?
      errors = report.errors.full_messages.join('; ')
      raise RuntimeError "Report to be imported is not valid: #{errors}"
    end
    report.state = :complete # Presume complete since it was exported
    report.save

    report.id
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