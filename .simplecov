# RM_INFO is set when using Rubymine.  In Rubymine, starting SimpleCov is
# controlled by running with coverage, so don't explicitly start coverage (and
# therefore generate a report) when in Rubymine.  This _will_ generate a report
# whenever `rake spec` is run.
#
# CI='true' on travis-ci.  Coverage is disabled there because with parallel_tests it's output is interleaved and we're
# not using coveralls to upload the coverage reports, so they're just wasting time being generated.
unless ENV['RM_INFO'] || ENV['CI'] == 'true'
	SimpleCov.start
end

SimpleCov.configure do
  # ignore this file
	add_filter '.simplecov'

	#
	# Changed Files in Git Group
	# @see http://fredwu.me/post/35625566267/simplecov-test-coverage-for-changed-files-only
	#

	untracked = `git ls-files --exclude-standard --others`
	unstaged = `git diff --name-only`
	staged = `git diff --name-only --cached`
	all = untracked + unstaged + staged
	changed_filenames = all.split("\n")

	add_group 'Changed' do |source_file|
		changed_filenames.detect { |changed_filename|
			source_file.filename.end_with?(changed_filename)
		}
	end

	#
	# Framework (msf) related groups
	#

	add_group 'Metasploit Framework', 'lib/msf'
	add_group 'Metasploit Framework (Base)', 'lib/msf/base'
	add_group 'Metasploit Framework (Core)', 'lib/msf/core'

	#
	# Other library groups
	#

	add_group 'Metasm', 'lib/metasm'
	add_group 'PacketFu', 'lib/packetfu'
	add_group 'Rex', 'lib/rex'
	add_group 'RKelly', 'lib/rkelly'
	add_group 'Ruby Mysql', 'lib/rbmysql'
	add_group 'Ruby Postgres', 'lib/postgres'
	add_group 'SNMP', 'lib/snmp'
	add_group 'Zip', 'lib/zip'

	#
	# Specs are reported on to ensure that all examples are being run and all
	# lets, befores, afters, etc are being used.
	#

	add_group 'Specs', 'spec'
end
