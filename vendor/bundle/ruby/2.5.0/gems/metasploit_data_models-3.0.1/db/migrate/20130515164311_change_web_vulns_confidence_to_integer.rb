# Changes web_vulns.confidence from text to integer as it is populated with integers.
class ChangeWebVulnsConfidenceToInteger < ActiveRecord::Migration
  #
  # CONSTANTS
  #

  # Columns in {TABLE} whose type needs to be change.
  COLUMN = :confidence
  # The correct type for {COLUMN}.
  NEW_TYPE = :integer
  # The incorrect type for {COLUMN}.
  OLD_TYPE = :text
  # The table in which {COLUMN} is defined.
  TABLE = :web_vulns

  #
  # Methods
  #

  # Changes web_vulns.confidence back to text
  #
  # @return [void]
  def down
    alter_type(:to => OLD_TYPE)
  end

  # Changes web_vulns.confidence to integer
  #
  # @return [void]
  def up
    alter_type(:to => NEW_TYPE)
  end

  private

  # Alters {COLUMN} type in {TABLE} from old to new type
  #
  # @param options [Hash{Symbol => #to_s}]
  # @option options [#to_s] :from The old type name.
  # @option options [#to_s] :to The new type name.
  def alter_type(options={})
    options.assert_valid_keys(:to)

    new = options.fetch(:to)

    execute "ALTER TABLE #{TABLE} ALTER COLUMN #{COLUMN} TYPE #{new} USING confidence::#{new}"
  end
end
