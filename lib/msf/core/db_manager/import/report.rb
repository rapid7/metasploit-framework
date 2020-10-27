module Msf::DBManager::Import::Report
  # @param report [REXML::Element] to be imported
  # @param args [Hash]
  # @param base_dir [String]
  def import_report(report, args, base_dir)
    tmp = args[:ifd][:zip_tmp]
    report_info = {}

    report.elements.each do |e|
      node_name  = e.name
      node_value = e.text

      # These need to be converted back to arrays:
      array_attrs = %w|addresses file-formats options sections|
      if array_attrs.member? node_name
        node_value = JSON.parse(node_value)
      end
      # Don't restore these values:
      skip_nodes = %w|id workspace-id artifacts|
      next if skip_nodes.member? node_name

      report_info[node_name.parameterize.underscore.to_sym] = node_value
    end
    # Use current workspace
    report_info[:workspace_id] = args[:workspace].id

    # Create report, need new ID to record artifacts
    report_id = report_report(report_info)

    # Handle artifacts
    report.elements.at('artifacts').elements.each do |artifact|
      artifact_opts = {}
      artifact.elements.each do |attr|
        skip_nodes = %w|id accessed-at|
        next if skip_nodes.member? attr.name

        symboled_attr = attr.name.parameterize.underscore.to_sym
        artifact_opts[symboled_attr] = attr.text
      end
      # Use new Report as parent
      artifact_opts[:report_id] = report_id
      # Update to full path
      artifact_opts[:file_path].gsub!(/^\./, tmp)

      report_artifact(artifact_opts)
    end
  end
end
