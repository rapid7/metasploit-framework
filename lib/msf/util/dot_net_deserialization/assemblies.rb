module Msf
module Util
module DotNetDeserialization
module Assemblies

  # see:
  #   * https://docs.microsoft.com/en-us/dotnet/standard/assembly/
  #   * https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/versions-and-dependencies
  #   * https://docs.microsoft.com/en-us/dotnet/standard/assembly/reference-strong-named
  class StrongName
    def initialize(name, version, public_key_token, culture: 'neutral')
      @name = name
      @version = version
      @public_key_token = public_key_token
      @culture = culture
    end

    attr_reader :name, :version, :public_key_token, :culture

    def to_s
      "#{name}, Version=#{version}, Culture=#{culture}, PublicKeyToken=#{public_key_token}"
    end

    def [](type_name)
      QualifiedName.new(type_name, self)
    end
  end

  # see: https://docs.microsoft.com/en-us/dotnet/api/system.type.assemblyqualifiedname
  class QualifiedName
    def initialize(name, assembly)
      @name = name
      @assembly = assembly
    end

    attr_reader :name, :assembly

    def to_s
      "#{name}, #{assembly}"
    end
  end

  VERSIONS = {
    '4.0.0.0' => {
      'mscorlib' => StrongName.new('mscorlib', '4.0.0.0', 'b77a5c561934e089'),
      'System' => StrongName.new('System', '4.0.0.0', 'b77a5c561934e089'),
      'System.Configuration.Install' => StrongName.new('System.Configuration.Install', '4.0.0.0', 'b03f5f7f11d50a3a')
    }
  }

end
end
end
end
