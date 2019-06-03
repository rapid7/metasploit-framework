
##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'msf/core'
require 'rex'
require 'msf/core/post/windows/registry'

lib = File.join(Msf::Config.install_root, "test", "lib")
$:.push(lib) unless $:.include?(lib)
require 'module_test'

class MetasploitModule < Msf::Post

  include Msf::ModuleTest::PostTest
  include Msf::Post::Windows::Registry

  def initialize(info={})
    super( update_info( info,
        'Name'          => 'registry_post_testing',
        'Description'   => %q{ This module will test Post::Windows::Registry API methods },
        'License'       => MSF_LICENSE,
        'Author'        => [
          'kernelsmith', # original
          'egypt',       # PostTest conversion
        ],
        'Platform'      => [ 'windows' ]
      ))
  end

  def test_0_registry_read
    it "should evaluate key existence" do
      k_exists = registry_key_exist?(%q#HKCU\Environment#)
      k_dne    = registry_key_exist?(%q#HKLM\\Non\Existent\Key#)

      (k_exists && !k_dne)
    end

    pending "should evaluate value existence" do
      # these methods are not implemented
      v_exists = registry_value_exist?(%q#HKCU\Environment#, "TEMP")
      v_dne    = registry_value_exist?(%q#HKLM\\Non\Existent\Key#, "asdf")

      (v_exists && !v_dne)
    end

    it "should read values" do
      ret = true
      valinfo = registry_getvalinfo(%q#HKCU\Environment#, "TEMP")
      ret &&= !!(valinfo["Data"])
      ret &&= !!(valinfo["Type"])

      valdata = registry_getvaldata(%q#HKCU\Environment#, "TEMP")
      ret &&= !!(valinfo["Data"] == valdata)

      valdata = registry_getvaldata(%q#HKCU\Environment#, "TEMP", REGISTRY_VIEW_NATIVE)
      ret &&= !!(valinfo["Data"] == valdata)
      valdata = registry_getvaldata(%q#HKCU\Environment#, "TEMP", REGISTRY_VIEW_32_BIT)
      ret &&= !!(valinfo["Data"] == valdata)
      valdata = registry_getvaldata(%q#HKCU\Environment#, "TEMP", REGISTRY_VIEW_64_BIT)
      ret &&= !!(valinfo["Data"] == valdata)

      ret
    end

    it "should return normalized values" do
      ret = true
      valinfo = registry_getvalinfo(%q#HKCU\Environment#, "TEMP")
      if (valinfo.nil?)
        ret = false
      else
        # type == 2 means string
        ret &&= !!(valinfo["Type"] == 2)
        ret &&= !!(valinfo["Data"].kind_of? String)

        valinfo = registry_getvalinfo(%q#HKLM\Software\Microsoft\Active Setup#, "DisableRepair")
        if (valinfo.nil?)
          ret = false
        else
          # type == 4 means DWORD
          ret &&= !!(valinfo["Type"] == 4)
          ret &&= !!(valinfo["Data"].kind_of? Numeric)
        end
      end

      ret
    end

    it "should enumerate keys and values" do
      ret = true
      # Has no keys, should return an empty Array
      keys = registry_enumkeys(%q#HKCU\Environment#)
      ret &&= (keys.kind_of? Array)

      vals = registry_enumvals(%q#HKCU\Environment#)
      ret &&= (vals.kind_of? Array)
      ret &&= (vals.count > 0)
      ret &&= (vals.include? "TEMP")

      ret
    end

  end

  def test_1_registry_write
    it "should create keys" do
      ret = registry_createkey(%q#HKCU\test_key#)
    end

    it "should write REG_SZ values" do
      ret = true
      registry_setvaldata(%q#HKCU\test_key#, "test_val_str", "str!", "REG_SZ")
      registry_setvaldata(%q#HKCU\test_key#, "test_val_dword", 1234, "REG_DWORD")
      valinfo = registry_getvalinfo(%q#HKCU\test_key#, "test_val_str")
      if (valinfo.nil?)
        ret = false
      else
        # type == REG_SZ means string
        ret &&= !!(valinfo["Type"] == 1)
        ret &&= !!(valinfo["Data"].kind_of? String)
        ret &&= !!(valinfo["Data"] == "str!")
      end

      ret
    end

    it "should write REG_DWORD values" do
      ret = true
      registry_setvaldata(%q#HKCU\test_key#, "test_val_dword", 1234, "REG_DWORD")
      valinfo = registry_getvalinfo(%q#HKCU\test_key#, "test_val_dword")
      if (valinfo.nil?)
        ret = false
      else
        ret &&= !!(valinfo["Type"] == 4)
        ret &&= !!(valinfo["Data"].kind_of? Numeric)
        ret &&= !!(valinfo["Data"] == 1234)
      end
      ret
    end

    it "should delete keys" do
      ret = registry_deleteval(%q#HKCU\test_key#, "test_val_str")
      valinfo = registry_getvalinfo(%q#HKCU\test_key#, "test_val_str")
      # getvalinfo should return nil for a non-existent key
      ret &&= (valinfo.nil?)
      ret &&= registry_deletekey(%q#HKCU\test_key#)
      # Deleting the key should delete all its values
      valinfo = registry_getvalinfo(%q#HKCU\test_key#, "test_val_dword")
      ret &&= (valinfo.nil?)

      ret
    end

    it "should create unicode keys" do
      ret = registry_createkey(%q#HKCU\σονσλυσιονεμκυε#)
    end

    it "should write REG_SZ unicode values" do
      ret = true
      registry_setvaldata(%q#HKCU\σονσλυσιονεμκυε#, "test_val_str", "дэлььякатезшимя", "REG_SZ")
      registry_setvaldata(%q#HKCU\σονσλυσιονεμκυε#, "test_val_dword", 1234, "REG_DWORD")
      valinfo = registry_getvalinfo(%q#HKCU\σονσλυσιονεμκυε#, "test_val_str")
      if (valinfo.nil?)
        ret = false
      else
        # type == REG_SZ means string
        ret &&= !!(valinfo["Type"] == 1)
        ret &&= !!(valinfo["Data"].kind_of? String)
        ret &&= !!(valinfo["Data"] == "дэлььякатезшимя")
      end

      ret
    end


    it "should delete unicode keys" do
      ret = registry_deleteval(%q#HKCU\σονσλυσιονεμκυε#, "test_val_str")
      valinfo = registry_getvalinfo(%q#HKCU\σονσλυσιονεμκυε#, "test_val_str")
      # getvalinfo should return nil for a non-existent key
      ret &&= (valinfo.nil?)
      ret &&= registry_deletekey(%q#HKCU\σονσλυσιονεμκυε#)
      # Deleting the key should delete all its values
      valinfo = registry_getvalinfo(%q#HKCU\σονσλυσιονεμκυε#, "test_val_dword")
      ret &&= (valinfo.nil?)

      ret
    end

  end

end


