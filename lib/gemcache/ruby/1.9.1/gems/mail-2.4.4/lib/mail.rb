# encoding: utf-8
module Mail # :doc:

  require 'date'
  require 'shellwords'

  require 'uri'
  require 'net/smtp'
  require 'mime/types'

  if RUBY_VERSION <= '1.8.6'
    begin
      require 'tlsmail'
    rescue LoadError
      raise "You need to install tlsmail if you are using ruby <= 1.8.6"
    end
  end

  if RUBY_VERSION >= "1.9.0"
    require 'mail/version_specific/ruby_1_9'
    RubyVer = Ruby19
  else
    require 'mail/version_specific/ruby_1_8'
    RubyVer = Ruby18
  end

  require 'mail/version'

  require 'mail/core_extensions/nil'
  require 'mail/core_extensions/object'
  require 'mail/core_extensions/string'
  require 'mail/core_extensions/shell_escape'
  require 'mail/core_extensions/smtp' if RUBY_VERSION < '1.9.3'
  require 'mail/indifferent_hash'

  # Only load our multibyte extensions if AS is not already loaded
  if defined?(ActiveSupport)
    require 'active_support/inflector'
  else
    require 'mail/core_extensions/string/access'
    require 'mail/core_extensions/string/multibyte'
    require 'mail/multibyte'
  end

  require 'mail/patterns'
  require 'mail/utilities'
  require 'mail/configuration'

  # Autoload mail send and receive classes.
  require 'mail/network'

  require 'mail/message'
  require 'mail/part'
  require 'mail/header'
  require 'mail/parts_list'
  require 'mail/attachments_list'
  require 'mail/body'
  require 'mail/field'
  require 'mail/field_list'

  require 'mail/envelope'

  parsers = %w[ rfc2822_obsolete rfc2822 address_lists phrase_lists
                date_time received message_ids envelope_from rfc2045
                mime_version content_type content_disposition
                content_transfer_encoding content_location ]

  parsers.each do |parser|
    begin
      # Try requiring the pre-compiled ruby version first
      require 'treetop/runtime'
      require "mail/parsers/#{parser}"
    rescue LoadError
      # Otherwise, get treetop to compile and load it
      require 'treetop/runtime'
      require 'treetop/compiler'
      Treetop.load(File.join(File.dirname(__FILE__)) + "/mail/parsers/#{parser}")
    end
  end

  # Autoload header field elements and transfer encodings.
  require 'mail/elements'
  require 'mail/encodings'
  require 'mail/encodings/base64'
  require 'mail/encodings/quoted_printable'

  require 'mail/matchers/has_sent_mail'

  # Finally... require all the Mail.methods
  require 'mail/mail'
end
