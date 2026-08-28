# minimal_uris_headers.profile
# Purpose: exercises custom URI routing + response headers; no encoding directives.
# Used by acceptance tests to confirm the handler registers profile URIs and that
# the payload reaches a session over those URIs.

set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)";

http-get {
    set uri "/jquery-3.3.1.min.js";

    client {
        header "Accept" "text/javascript, application/javascript";
        header "Referer" "https://www.example.com/";

        metadata {
            parameter "callback";
        }
    }

    server {
        header "Content-Type" "application/javascript; charset=utf-8";
        header "Cache-Control" "max-age=604800";

        output {
            print;
        }
    }
}

http-post {
    set uri "/jquery-3.3.1.min.js/save";

    client {
        header "Content-Type" "application/octet-stream";

        id {
            parameter "id";
        }

        output {
            print;
        }
    }

    server {
        header "Content-Type" "text/plain; charset=utf-8";

        output {
            print;
        }
    }
}
