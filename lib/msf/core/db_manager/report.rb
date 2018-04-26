#
# Standard library
#

require 'fileutils'

module Msf::DBManager::Report
  # TODO This method does not attempt to find. It just creates
  # a report based on the passed params.
  def find_or_create_report(opts)
    report_report(opts)
  end

  # Creates a ReportArtifact based on passed parameters.
  # @param opts [Hash] of ReportArtifact attributes
  def report_artifact(opts)
    return if not active

    artifacts_dir = Report::ARTIFACT_DIR
    tmp_path = opts[:file_path]
    artifact_name = File.basename tmp_path
    new_path = File.join(artifacts_dir, artifact_name)
    created = opts.delete(:created_at)
    updated = opts.delete(:updated_at)

    unless File.exist? tmp_path
      raise Msf::DBImportError 'Report artifact file to be imported does not exist.'
    end

    unless (File.directory?(artifacts_dir) && File.writable?(artifacts_dir))
      raise Msf::DBImportError "Could not move report artifact file to #{artifacts_dir}."
    end

    if File.exist? new_path
      unique_basename = "#{(Time.now.to_f*1000).to_i}_#{artifact_name}"
      new_path = File.join(artifacts_dir, unique_basename)
    end

    FileUtils.copy(tmp_path, new_path)
    opts[:file_path] = new_path
    artifact = ReportArtifact.new(opts)
    artifact.created_at = created
    artifact.updated_at = updated

    unless artifact.valid?
      errors = artifact.errors.full_messages.join('; ')
      raise "Artifact to be imported is not valid: #{errors}"
    end
    artifact.save
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
      raise "Report to be imported is not valid: #{errors}"
    end
    report.state = :complete # Presume complete since it was exported
    report.save

    report.id
  }
  end

  #
  # This methods returns a list of all reports in the database
  #
  def reports(wspace=framework.db.workspace)
  ::ActiveRecord::Base.connection_pool.with_connection {
    wspace.reports
  }
  end
end
