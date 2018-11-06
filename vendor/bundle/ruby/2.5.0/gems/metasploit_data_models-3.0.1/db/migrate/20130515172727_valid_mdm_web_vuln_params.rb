class ValidMdmWebVulnParams < ActiveRecord::Migration
  # Don't put back the bad format because there's not way to figure our which of the [] were '' before {#up} and
  # which were `[]` before {#up}.
  #
  # @return [void]
  def down
  end

  # Changes any Mdm::WebVuln#params with value `''` to value `[]`.
  #
  # @return [void]
  def up
    # Can't search serialized columns, so have to load all the Mdm::WebVulns in memory
    Mdm::WebVuln.find_each do |web_vuln|
      if web_vuln.invalid?
        # cast nil, '' and {} to correct [].
        if web_vuln.params.blank?
          web_vuln.params = []
        end

        # If its still invalid have to destroy the Mdm::WebVuln or a different export error could occur.
        if web_vuln.invalid?
          web_vuln.destroy
        else
          web_vuln.save!
        end
      end
    end
  end
end
