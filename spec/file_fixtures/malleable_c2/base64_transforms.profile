# base64_transforms.profile
# Purpose: exercises base64 encoding on server->client GET responses and
# prepend/append transforms on client->server POST bodies.
# Used by acceptance tests to confirm wrap/unwrap encoding round-trips correctly.

set useragent "Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)";

http-get {
    set uri "/updates/check";

    client {
        header "Accept" "application/json";

        metadata {
            parameter "v";
        }
    }

    server {
        header "Content-Type" "application/octet-stream";

        output {
            base64;
            prepend "START_";
            append "_END";
            print;
        }
    }
}

http-post {
    set uri "/updates/report";

    client {
        header "Content-Type" "application/octet-stream";

        id {
            parameter "uid";
        }

        output {
            base64;
            print;
        }
    }

    server {
        header "Content-Type" "text/plain";

        output {
            print;
        }
    }
}
