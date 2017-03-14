Given /^I unset the environment variables:$/ do |table|
  table.hashes.each do |row|
    variable = row['variable'].to_s.upcase

    # @todo add extension to Announcer
    announcer.instance_eval do
      if @options[:env]
        print "$ unset #{variable}"
      end
    end

    current_value = ENV.delete(variable)

    # if original_env already has the key, then the true original was already recorded from a previous unset or set,
    # so don't record the current value as it will cause ENV not to be restored after the Scenario.
    unless original_env.key? variable
      original_env[variable] = current_value
    end
  end
end