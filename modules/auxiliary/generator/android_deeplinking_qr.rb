require 'msf/core'
require 'chunky_png'
require 'rqrcode'


class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::FILEFORMAT

  # How to use this module:
  #
  # 1. Load the module:
  # 2. Set the deep link scheme (like for Wechat lets say):
  #    `use auxiliary/generator/android_deeplinking_qr`
  #
  #    `set DEEPLINK_SCHEME weixin://`
  #
  # 3. Set the deep link path :
  #    `set DEEPLINK_PATH dl/scanqr?type=qr `
  #
  # 4. Specify the output filename for the generated QR code:
  #    `set FILENAME wechat_qr.png`
  #
  # 5. Run the module to generate the QR code:
  #    `run`

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'Android Deep Link QR Code Payload Generator',
      'Description'    => %q{
        This module make QR code with ANdroid Deep Link.
        When user scan QR, phone open app with deep link.
        Can use for test app security or social engineering.
      },
      'Author'         => [ 'ctkqiang' ],
      'License'        => MSF_LICENSE
    ))

    register_options([
      OptEnum.new('DEEPLINK_SCHEME', [true, 'Choose deep link scheme', 'weixin://', [
        'weixin://',
        'grab://',
        'boost://',
        'alipay://',
        'fb://',
        'instagram://',
        'twitter://',
        'line://',
        'telegram://',
        'whatsapp://',
        'tiktok://',
        'shopee://',
        'lazada://',
        'gpay://',
        'applepay://',
        'youtube://',
        'spotify://',
        'linkedin://',
        'pinterest://',
        'snapchat://',
        'paypal://',
        'skype://',
        'discord://',
        'slack://',
        'zoomus://',
        'meet://',
        'waze://',
        'maps://',
        'uber://',
        'lyft://',
        'cameraplus://',
        'vimeo://',
        'tumblr://',
        'reddit://',
        'hulu://',
        'netflix://',
        'soundcloud://',
        'deezer://',
        'tidal://',
        'messenger://',
        'fb-messenger://',
        'skype-for-business://',
        'teams://',
        'onedrive://',
        'dropbox://',
        'box://',
        'zoom://',
        'twitch://',
        'quora://',
        'medium://',
        'goodreads://',
        'yelp://',
        'tripadvisor://',
        'booking://',
        'airbnb://',
        'grabpay://',
        'wechatpay://',
        'ocbc://',
        'maybank2u://',
        'rhb://',
        'cimb://',
        'dbs://',
        'hsbc://',
        'standardchartered://',
        'custom://'
      ]]),
      OptString.new('CUSTOM_SCHEME', [false, 'If choose custom, put scheme here', 'myapp://']),
      OptString.new('DEEPLINK_PATH', [false, 'Deep link path and parameters', 'pay?amount=100']),
      OptString.new('FILENAME', [true, 'QR code output file', 'deeplink_qr.png']),
      OptInt.new('SIZE', [true, 'QR code size in pixel', 400])
    ])

    # List for reference
    # maybe add more  in future


  end

  def run
    scheme = datastore['DEEPLINK_SCHEME']
    
    if scheme == 'custom://'
      custom_scheme = datastore['CUSTOM_SCHEME']
      if custom_scheme.empty?
        print_error("Please set CUSTOM_SCHEME option")
        return
      end

      scheme = custom_scheme
    end

    path = datastore['DEEPLINK_PATH'] || ""
    
    if path.empty?
      target_deep_link = scheme
    else
      if path.start_with?('/')
        target_deep_link = scheme + path
      else
        target_deep_link = scheme + '/' + path
      end
    end

    print_status("Start generate QR code for deep link...")
    print_status("Deep Link: #{target_deep_link}")
    
    app_name = get_app_name(scheme)
    
    print_status("This deep link will open: #{app_name}")

    begin
      generate_qr_code(target_deep_link)
    
      print_good("QR code generate success: #{datastore['FILENAME']}")
      print_warning("When user scan this QR, #{app_name} will open with deep link")
      
    rescue => e
      print_error("Generate QR code fail: #{e.message}")
      if e.message.include?('missing constant') || e.message.include?('require')
        print_error("Maybe need install gem: gem install rqrcode chunky_png")
      end
    end
  end

  private

  def generate_qr_code(url)
    qrcode = RQRCode::QRCode.new(url)
    
    png = qrcode.as_png(
      size: datastore['SIZE'],
      border_modules: 1,
      module_px_size: 6,
      fill: 'white',
      color: 'black'
    )
    
    File.binwrite(datastore['FILENAME'], png.to_s)
  end

  def get_app_name(scheme)
    case scheme
    when 'weixin://' then 'WeChat'
    when 'grab://' then 'Grab'
    when 'boost://' then 'Boost'
    when 'alipay://' then 'Alipay'
    when 'fb://' then 'Facebook'
    when 'instagram://' then 'Instagram'
    when 'twitter://' then 'Twitter'
    when 'line://' then 'LINE'
    when 'telegram://' then 'Telegram'
    when 'whatsapp://' then 'WhatsApp'
    when 'tiktok://' then 'TikTok'
    when 'shopee://' then 'Shopee'
    when 'lazada://' then 'Lazada'
    when 'gpay://' then 'Google Pay'
    when 'applepay://' then 'Apple Pay'
    when 'youtube://' then 'YouTube'
    when 'spotify://' then 'Spotify'
    when 'linkedin://' then 'LinkedIn'
    when 'pinterest://' then 'Pinterest'
    when 'snapchat://' then 'Snapchat'
    when 'paypal://' then 'PayPal'
    when 'skype://' then 'Skype'
    when 'discord://' then 'Discord'
    when 'slack://' then 'Slack'
    when 'zoomus://', 'zoom://' then 'Zoom'
    when 'meet://' then 'Google Meet'
    when 'waze://' then 'Waze'
    when 'maps://' then 'Maps'
    when 'uber://' then 'Uber'
    when 'lyft://' then 'Lyft'
    when 'cameraplus://' then 'Camera+'
    when 'vimeo://' then 'Vimeo'
    when 'tumblr://' then 'Tumblr'
    when 'reddit://' then 'Reddit'
    when 'hulu://' then 'Hulu'
    when 'netflix://' then 'Netflix'
    when 'soundcloud://' then 'SoundCloud'
    when 'deezer://' then 'Deezer'
    when 'tidal://' then 'Tidal'
    when 'messenger://', 'fb-messenger://' then 'Messenger'
    when 'skype-for-business://' then 'Skype for Business'
    when 'teams://' then 'Microsoft Teams'
    when 'onedrive://' then 'OneDrive'
    when 'dropbox://' then 'Dropbox'
    when 'box://' then 'Box'
    when 'twitch://' then 'Twitch'
    when 'quora://' then 'Quora'
    when 'medium://' then 'Medium'
    when 'goodreads://' then 'Goodreads'
    when 'yelp://' then 'Yelp'
    when 'tripadvisor://' then 'Tripadvisor'
    when 'booking://' then 'Booking.com'
    when 'airbnb://' then 'Airbnb'
    when 'grabpay://' then 'GrabPay'
    when 'wechatpay://' then 'WeChat Pay'
    when 'ocbc://' then 'OCBC Bank'
    when 'maybank2u://' then 'Maybank2u'
    when 'rhb://' then 'RHB Bank'
    when 'cimb://' then 'CIMB Bank'
    when 'dbs://' then 'DBS Bank'
    when 'hsbc://' then 'HSBC'
    when 'standardchartered://' then 'Standard Chartered'
    else 'Unknown App'
    end
  end

end