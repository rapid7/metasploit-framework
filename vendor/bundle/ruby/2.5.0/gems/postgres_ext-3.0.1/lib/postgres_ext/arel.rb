
gdep = Gem::Dependency.new('activerecord', '~> 4.2.0')
ar_version_cutoff = gdep.matching_specs.sort_by(&:version).last

require 'postgres_ext/arel/nodes'
if ar_version_cutoff
  require 'postgres_ext/arel/4.2/predications'
  require 'postgres_ext/arel/4.2/visitors'
else
  require 'postgres_ext/arel/4.1/predications'
  require 'postgres_ext/arel/4.1/visitors'
end

