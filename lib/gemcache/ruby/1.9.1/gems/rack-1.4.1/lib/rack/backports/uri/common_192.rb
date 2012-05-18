# :stopdoc:

# Stolen from ruby core's uri/common.rb @32618ba to fix DoS issues in 1.9.2
#
# https://github.com/ruby/ruby/blob/32618ba7438a2247042bba9b5d85b5d49070f5e5/lib/uri/common.rb
#
# Issue:
# http://redmine.ruby-lang.org/issues/5149
#
# Relevant Fixes:
# https://github.com/ruby/ruby/commit/b5f91deee04aa6ccbe07c23c8222b937c22a799b
# https://github.com/ruby/ruby/commit/93177c1e5c3906abf14472ae0b905d8b5c72ce1b
#
# This should probably be removed once there is a Ruby 1.9.2 patch level that
# includes this fix.

require 'uri/common'

module URI
  def self.decode_www_form(str, enc=Encoding::UTF_8)
    return [] if str.empty?
    unless /\A#{WFKV_}=#{WFKV_}(?:[;&]#{WFKV_}=#{WFKV_})*\z/o =~ str
      raise ArgumentError, "invalid data of application/x-www-form-urlencoded (#{str})"
    end
    ary = []
    $&.scan(/([^=;&]+)=([^;&]*)/) do
      ary << [decode_www_form_component($1, enc), decode_www_form_component($2, enc)]
    end
    ary
  end

  def self.decode_www_form_component(str, enc=Encoding::UTF_8)
    if TBLDECWWWCOMP_.empty?
      tbl = {}
      256.times do |i|
        h, l = i>>4, i&15
        tbl['%%%X%X' % [h, l]] = i.chr
        tbl['%%%x%X' % [h, l]] = i.chr
        tbl['%%%X%x' % [h, l]] = i.chr
        tbl['%%%x%x' % [h, l]] = i.chr
      end
      tbl['+'] = ' '
      begin
        TBLDECWWWCOMP_.replace(tbl)
        TBLDECWWWCOMP_.freeze
      rescue
      end
    end
    raise ArgumentError, "invalid %-encoding (#{str})" unless /\A[^%]*(?:%\h\h[^%]*)*\z/ =~ str
    str.gsub(/\+|%\h\h/, TBLDECWWWCOMP_).force_encoding(enc)
  end

  remove_const :WFKV_
  WFKV_ = '(?:[^%#=;&]*(?:%\h\h[^%#=;&]*)*)' # :nodoc:
end
