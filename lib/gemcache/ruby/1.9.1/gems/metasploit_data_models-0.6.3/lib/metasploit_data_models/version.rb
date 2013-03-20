module MetasploitDataModels
  # MetasploitDataModels follows the {http://semver.org/  Semantic Versioning Specification}.  At this time, the API
  # is considered unstable because although the database migrations have moved from
  # metasploit-framework/data/sql/migrate to db/migrate in this project, not all models have specs that verify the
  # migrations (with have_db_column and have_db_index) and certain models may not be shared between metasploit-framework
  # and pro, so models may be removed in the future.  Because of the unstable API the version should remain below 1.0.0
  VERSION = '0.6.3'
end
