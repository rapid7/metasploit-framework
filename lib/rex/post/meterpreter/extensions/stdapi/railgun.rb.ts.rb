# -*- coding: binary -*-
$:.unshift(File.join(File.dirname(__FILE__)))
$:.unshift(File.join(File.dirname(__FILE__), '..', '..','..','..','..','..', 'lib'))

require 'test/unit'
require 'rex'

require 'railgun/api_constants.rb.ut'
require 'railgun/type/pointer_util.rb.ut'
require 'railgun/platform_util.rb.ut'
require 'railgun/buffer_item.rb.ut'
require 'railgun/dll_function.rb.ut'
require 'railgun/dll_helper.rb.ut'
require 'railgun/win_const_manager.rb.ut'
require 'railgun/dll.rb.ut.rb'
require 'railgun/dll_wrapper.rb.ut.rb'
require 'railgun/railgun.rb.ut.rb'
require 'railgun/win_const_manager.rb.ut.rb'
