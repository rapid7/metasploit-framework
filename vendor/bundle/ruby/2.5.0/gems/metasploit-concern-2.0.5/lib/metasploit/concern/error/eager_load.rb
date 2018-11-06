# Exception raised when a `Rails::Engine` has left its `'app/concerns'` path as `eager_load: true`
class Metasploit::Concern::Error::EagerLoad < Metasploit::Concern::Error::Base
  # @param engine [Rails::Engine] `Rails::Engine` where `engine.paths['app/concerns'].eager_load?` is `true`.
  def initialize(engine)
    @engine = engine
    engine_name = engine.class.name
    super(
        "#{engine_name}'s `app/concerns` is marked as `eager_load: true`.  This will cause circular dependency " \
        "errors when the concerns are loaded.  Declare `app/concerns` to stop it from inheriting `eager_load: true` " \
        "from `app`: \n" \
        "\n" \
        "  class #{engine_name} < Rails::Engine\n" \
        "    config.paths.add 'app/concerns', autoload: true\n" \
        "  end\n"
    )
  end
end