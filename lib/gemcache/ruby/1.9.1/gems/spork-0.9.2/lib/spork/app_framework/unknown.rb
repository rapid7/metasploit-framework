# This is used if no supported appliction framework is detected
class Spork::AppFramework::Unknown < Spork::AppFramework
  def entry_point
    nil
  end
end