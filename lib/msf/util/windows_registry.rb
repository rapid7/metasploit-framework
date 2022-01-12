module Msf::Util::WindowsRegistry

  def self.parse(hive_data, name: nil)
    RegistryParser.new(hive_data, name: name)
  end

end
