# Exception raised when a `Rails::Engine` has left its `'app/concerns'` path as `autoload_load: false`
class Metasploit::Concern::Error::SkipAutoload < Metasploit::Concern::Error::Base
  # @param engine [Rails::Engine] `Rails::Engine` where `engine.paths['app/concerns'].autoload?` is `false`.
  def initialize(engine)
    @engine = engine
    engine_name = engine.class.name
    super(
        "#{engine_name}'s `app/concerns` is marked as `autoload: false`.  Declare `app/concerns` as autoloading:\n" \
        "\n" \
        "  class #{engine_name} < Rails::Engine\n" \
        "    config.paths.add 'app/concerns', autoload: true\n" \
        "  end\n"
    )
  end
end