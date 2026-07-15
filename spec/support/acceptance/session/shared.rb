module Acceptance::Session::Shared
    # Known intermittent failures in socket channel tests.
    #
    # Two categories:
    # 1. Real transport limitations — UDP over HTTP polling is timing-sensitive;
    #    data may not arrive within the test's timeout window depending on poll intervals.
    # 2. SIGINT artifacts — our cleanup loop sends SIGINT to unblock hung channel
    #    operations; if SIGINT fires mid-test the module raises Interrupt, producing
    #    the bracketed "Exception: Interrupt:" format in the output.
    SOCKET_CHANNEL_FLAKES = [
        # Real UDP transport limitations
        ["[-] FAILED: [UDP] Receives data from the peer", { flaky: true }],
        ["[-] [[UDP] Has the correct peer information] FAILED: [UDP] Has the correct peer information", { flaky: true }],
        ["[-] [[UDP] Has the correct peer information] Timed out after 5s waiting to receive data from peer", { flaky: true }],
        # SIGINT fired during UDP test
        ["[-] [[UDP] Has the correct peer information] Exception: Interrupt: ", { flaky: true }],
        # Real TCP close-event timing limitation
        ["[-] FAILED: [TCP-Server] Propagates close events to the server", { flaky: true }],
        # SIGINT fired during TCP close-event tests
        ["[-] [[TCP-Client] Propagates close events from the peer] FAILED: [TCP-Client] Propagates close events from the peer", { flaky: true }],
        ["[-] [[TCP-Client] Propagates close events from the peer] Exception: Interrupt: ", { flaky: true }],
        ["[-] [[TCP-Server] Propagates close events to the peer] FAILED: [TCP-Server] Propagates close events to the peer", { flaky: true }],
        ["[-] [[TCP-Server] Propagates close events to the peer] Exception: Interrupt: ", { flaky: true }],
        ["[-] [[TCP-Server] Propagates close events from the peer] FAILED: [TCP-Server] Propagates close events from the peer", { flaky: true }],
        ["[-] [[TCP-Server] Propagates close events from the peer] Exception: Interrupt: ", { flaky: true }],
        ["[-] [[TCP-Server] Sends data to the peer] FAILED: [TCP-Server] Sends data to the peer", { flaky: true }],
        ["[-] [[TCP-Server] Sends data to the peer] Exception: Interrupt: ", { flaky: true }],
        # msfconsole prints this when SIGINT interrupts a running post module
        ["[-] Post interrupted by the console user", { flaky: true }]
    ]
end
