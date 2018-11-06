unless Hash.respond_to? :try_convert
  require 'backports/tools/arguments'

  def Hash.try_convert(x)
    Backports.try_convert(x, Hash, :to_hash)
  end
end
