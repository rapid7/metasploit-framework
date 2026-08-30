module Acceptance::Session::Shared
    # TODO: Should be resolved
    SOCKET_CHANNEL_FLAKES = [
        ["[-] FAILED: [UDP] Receives data from the peer", { flaky: true }],
        ["[-] FAILED: [TCP-Server] Propagates close events to the server", { flaky: true }]
    ]
end
