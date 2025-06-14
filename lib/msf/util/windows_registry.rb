module Msf::Util::WindowsRegistry

  def self.parse(hive_data, name: nil, root: nil)
    RegistryParser.new(hive_data, name: name, root: root)
  end

end
