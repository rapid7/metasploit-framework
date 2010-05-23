#!/usr/bin/env ruby

require 'erb'

class Template
  attr_accessor :template, :result

  def initialize(filename)
    begin
      f = File.new(filename)
      @template = f.read
    rescue Errno::ENOENT
    end
  end

  def parse
    @result = ERB.new(@template).result(binding)
  end

  def get_result
    result
  end
end

class Source < Template
  attr_accessor :__CAL
  attr_accessor :__NR_execve
  attr_accessor :__NR_getpeername
  attr_accessor :__NR_accept
  attr_accessor :__NR_listen
  attr_accessor :__NR_bind
  attr_accessor :__NR_socket
  attr_accessor :__NR_connect
  attr_accessor :__NR_close
  attr_accessor :__NR_kfcntl
  attr_accessor :__cal
  attr_accessor :_cal
  attr_accessor :cal
  attr_accessor :ver

  def initialize(filename)
    @__CAL = 2047
    @__cal = "\x38\x5d"
    @_cal  = Hash.new
    @cal   = Hash.new
    @ver   = String.new

    @execve      = ''
    @getpeername = ''
    @accept      = ''
    @listen      = ''
    @bind        = ''
    @socket      = ''
    @connect     = ''
    @close       = ''
    @kfcntl      = ''

    super(filename)
  end

  def parse
    __NC_execve      = -(__CAL - __NR_execve)
    __NC_getpeername = -(__CAL - __NR_getpeername)
    __NC_accept      = -(__CAL - __NR_accept)
    __NC_listen      = -(__CAL - __NR_listen)
    __NC_bind        = -(__CAL - __NR_bind)
    __NC_socket      = -(__CAL - __NR_socket)
    __NC_connect     = -(__CAL - __NR_connect)
    __NC_close       = -(__CAL - __NR_close)
    __NC_kfcntl      = -(__CAL - __NR_kfcntl)

    _cal[ver] = {
      :execve      => __cal + [__NC_execve].pack('n'),
      :getpeername => __cal + [__NC_getpeername].pack('n'),
      :accept      => __cal + [__NC_accept].pack('n'),
      :listen      => __cal + [__NC_listen].pack('n'),
      :bind        => __cal + [__NC_bind].pack('n'),
      :socket      => __cal + [__NC_socket].pack('n'),
      :connect     => __cal + [__NC_connect].pack('n'),
      :close       => __cal + [__NC_close].pack('n'),
      :kfcntl      => __cal + [__NC_kfcntl].pack('n'),
    }

    cal = Hash.new
    cal[ver] = Hash.new

    _cal[ver].each_pair do |key, value|
      cal[ver][key] = Array.new
      cal[ver][key] << String.new
      cal[ver][key][-1] << '#ifdef AIX%s' % ver.delete('.')
      cal[ver][key][-1] << "\n"
      cal[ver][key][-1] << '"'.rjust(5)
      value.each_byte do |c|
        cal[ver][key][-1] << '\x%02x' % c
      end
      cal[ver][key][-1] << '"'.ljust(7)
      cal[ver][key][-1] << '/*  cal     r2,-%d(r29)' %
          (65536 - value.unpack('nn')[1])
      cal[ver][key][-1] << '*/'.rjust(15)
      cal[ver][key][-1] << "\n"
      cal[ver][key][-1] << "#endif"
      cal[ver][key][-1] << "\n"
    end

    cal.each_pair do |key, ver|
      ver.each_pair do |key, value|
        instance_variable_get("@#{key}").concat(value[-1])
      end
    end

    super
  end
end

class Parser
  def initialize(filename)
    @src = Source.new(filename)
  end

  def parse
vers = [
  '6.1.4',
  '6.1.3',
  '6.1.2',
  '6.1.1',
  '6.1.0',
  '5.3.10',
  '5.3.9',
  '5.3.8',
  '5.3.7',
]

vers.each do |ver|
  case ver
  when '6.1.4'
    __NR_execve      = 7
    __NR_getpeername = 211
    __NR_accept      = 237
    __NR_listen      = 240
    __NR_bind        = 242
    __NR_socket      = 243
    __NR_connect     = 244
    __NR_close       = 278
    __NR_kfcntl      = 658

  when '6.1.3'
    __NR_execve      = 7
    __NR_getpeername = 205
    __NR_accept      = 232
    __NR_listen      = 235
    __NR_bind        = 237
    __NR_socket      = 238
    __NR_connect     = 239
    __NR_close       = 272
    __NR_kfcntl      = 644

  when '6.1.2'
    __NR_execve      = 7
    __NR_getpeername = 205
    __NR_accept      = 232
    __NR_listen      = 235
    __NR_bind        = 237
    __NR_socket      = 238
    __NR_connect     = 239
    __NR_close       = 272
    __NR_kfcntl      = 635

  when '6.1.1'
    __NR_execve      = 7
    __NR_getpeername = 202
    __NR_accept      = 229
    __NR_listen      = 232
    __NR_bind        = 234
    __NR_socket      = 235
    __NR_connect     = 236
    __NR_close       = 269
    __NR_kfcntl      = 614

  when '6.1.0'
    __NR_execve      = 6
    __NR_getpeername = 203
    __NR_accept      = 229
    __NR_listen      = 232
    __NR_bind        = 234
    __NR_socket      = 235
    __NR_connect     = 236
    __NR_close       = 269
    __NR_kfcntl      = 617

  when '5.3.10', '5.3.9', '5.3.8', '5.3.7'
    __NR_execve      = 6
    __NR_getpeername = 198
    __NR_accept      = 214
    __NR_listen      = 215
    __NR_bind        = 216
    __NR_socket      = 217
    __NR_connect     = 218
    __NR_close       = 245
    __NR_kfcntl      = 493

  end

  @src.__NR_execve      = __NR_execve
  @src.__NR_getpeername = __NR_getpeername
  @src.__NR_accept      = __NR_accept
  @src.__NR_listen      = __NR_listen
  @src.__NR_bind        = __NR_bind
  @src.__NR_socket      = __NR_socket
  @src.__NR_connect     = __NR_connect
  @src.__NR_close       = __NR_close
  @src.__NR_kfcntl      = __NR_kfcntl

  @src.ver = ver
  @src.parse
end
  end

  def get_result
    @src.get_result
  end
end

filename = ARGV.shift || exit

parser = Parser.new(filename)
parser.parse
print parser.get_result

