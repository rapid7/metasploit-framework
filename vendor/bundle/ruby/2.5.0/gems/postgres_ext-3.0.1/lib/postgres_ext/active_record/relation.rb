## TODO: Change to ~> 4.2.0 on gem release

gdep = Gem::Dependency.new('activerecord', '~> 4.2.0.beta4')
ar_version_cutoff = gdep.matching_specs.sort_by(&:version).last

require 'postgres_ext/active_record/relation/merger'
require 'postgres_ext/active_record/relation/query_methods'
if ar_version_cutoff
  require 'postgres_ext/active_record/relation/predicate_builder/array_handler'
else
  require 'postgres_ext/active_record/relation/predicate_builder'
end

