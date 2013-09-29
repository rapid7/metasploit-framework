module Msf::Auxiliary::Report::Workspace
  def inside_workspace_boundary?(ip)
    # allowed if database not connected
    allowed = true

    framework.db.with_connection do
      allowed = myworkspace.allow_actions_on?(ip)
    end

    allowed
  end

  def myworkspace
    @myworkspace ||= framework.db.with_connection {
      Mdm::Workspace.where(name: workspace).first
    }
  end
end