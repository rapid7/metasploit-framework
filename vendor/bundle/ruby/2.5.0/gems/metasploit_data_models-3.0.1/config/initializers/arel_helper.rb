# Including arel-helpers in all active record models.
# https://github.com/camertron/arel-helpers

ActiveRecord::Base.send(:include, ArelHelpers::ArelTable)
ActiveRecord::Base.send(:include, ArelHelpers::JoinAssociation)
