## Vulnerable Application

This is a passive lookup module for [DarkEye](https://darkeye.io/), not an exploit.
It sends a domain to [HaveIBeenRansom](https://haveibeenransom.com/howapi),
[Breach House](https://breach.house/docs), or both, depending on the configured keys.
It does not contact the queried domain or retrieve leaked records or credentials.
API access requires a key for each configured product; web access and API access
are separate. Obtain keys through the respective product's account or access process.

The module saves one `darkeye.metadata` JSON loot file. Each record has a product,
category, id, title, website, group, country and discovery date. It discards other
fields, including descriptions, proof files and leak-site links. Text is limited
to 512 characters and dates to 10 characters. Control characters are removed.
A listing does not confirm an incident or establish maliciousness. An empty report
does not establish that the domain is safe.

Requests use HTTPS with certificate-chain and hostname verification, bearer headers,
no redirects, no automatic retries, and a separate connection for each request.
Cookies are neither retained nor forwarded. The transport has no HTTP trace subscriber
and does not use environment proxy settings or HTTP authentication settings.
Only the configured API service receives its key. Keys must not be included in
resource scripts, screenshots, exported framework configurations or PR evidence.

HaveIBeenRansom uses the domain metadata endpoint, with bounded pagination. Breach
House uses the cross-source search endpoint. Its free-text hits are filtered to
an exact domain or subdomain in the website. A complete hostname in the title
can match only when the website is absent. Categories are ransomware, breach, lead
and stealer listings where supplied by the API. The module does not request full
stealer records.

If one product fails, the other product's completed result remains in the report.
If a later HaveIBeenRansom page fails, its incomplete records are discarded. If all
configured products fail, the module fails without saving an empty success report.
Malformed responses also count as failures. `status` is `partial` when there are
errors or retrieval limits; `truncated` identifies a retrieval limit. A partial
report may contain zero records because filtering happens after the API result cap.

## Verification Steps

1. Start `msfconsole` and run `use auxiliary/gather/darkeye_search`.
1. Set `DOMAIN` to a domain you are authorized to investigate, such as a controlled test domain.
1. Configure `HIBR_API_KEY`, `BREACHHOUSE_API_KEY`, or both. Avoid recording the values in shared console output.
1. Run `run`. Expect a DarkEye listing count, completion status, product names and a JSON loot path.
1. Inspect the JSON report locally. Each record must identify its product and category; no raw leaked data should be present.
1. With both products configured, use an invalid key for one product. Expect a warning and a partial report from the other product.
1. Unset both keys and run again. Expect an option validation error without an API request.

Offline checks (no keys or network access):

```shell
bundle exec rspec --options /dev/null --require msfenv spec/modules/auxiliary/gather/darkeye_search_spec.rb
bundle exec rubocop modules/auxiliary/gather/darkeye_search.rb spec/modules/auxiliary/gather/darkeye_search_spec.rb
bundle exec ruby tools/dev/msftidy.rb modules/auxiliary/gather/darkeye_search.rb
bundle exec ruby tools/dev/msftidy_docs.rb documentation/modules/auxiliary/gather/darkeye_search.md
```

## Options

### DOMAIN

A plain ASCII or punycode domain. URLs, IP addresses, query strings and single-label
names are rejected. Uppercase and a single trailing dot are normalized locally.

### HIBR_API_KEY / BREACHHOUSE_API_KEY

A key for each product you want to query. Either key works independently; at least
one is required. A configured product receives the target domain.

### MAX_PAGES / MAX_RECORDS / SEARCH_LIMIT

`MAX_PAGES` defaults to 5 HaveIBeenRansom pages (range 1–20). `MAX_RECORDS` defaults
to 100 retained records per product (range 1–500). `SEARCH_LIMIT` defaults to 25
Breach House results requested per source (range 1–200). These are module bounds,
not subscription allowances. With defaults, there are at most five HaveIBeenRansom
calls and one Breach House call. The record cap can stop pagination earlier.

### HttpClientTimeout

Request timeout in seconds, default 30, range 1–120.

## Scenarios

These scenarios were drafted with AI assistance based on automated `msfconsole` runs
recorded on 2026-11-04. They do not describe manual execution. The test environment
was Debian 12, Ruby 3.3.6 and Metasploit source at
`08c9e7ac481402838511aa719c596a2f81c5dcbf`, with this module added and the repository's
locked dependencies. The repository pins Ruby 3.3.13; that patch version was not tested.

The runs used `use auxiliary/gather/darkeye_search`. A Ruby block in a
resource script then set the active module's datastore and called `mod.run` for each
case. Valid keys were loaded from a private environment variable; no valid key
values were embedded in the script or displayed as console commands. The captured
output below omits listing contents and replaces local loot paths with
`<local loot path>`. The counts are specific to these runs and may change as the API data changes.

### Both products with bounded results

1. Load `auxiliary/gather/darkeye_search` in `msfconsole`.
1. Set `DOMAIN` to `example.com` and configure valid `HIBR_API_KEY` and `BREACHHOUSE_API_KEY` values privately.
1. Set `MAX_PAGES` to `1`, `MAX_RECORDS` to `10` and `SEARCH_LIMIT` to `5`.
1. Run the module. The recorded run used `mod.run` inside the resource script.
1. Inspect the saved JSON report locally for product labels, completion status, truncation and errors.

The report contained 13 listings across both products, with `status=partial`,
`truncated=true` and no product errors. The record cap applies per product, so the
combined count can exceed 10. Reaching a retrieval limit makes this report partial.

```text
[*] LIVE A: both products, bounded example.com lookup
[*] DarkEye: 13 listing(s); status=partial; products=HaveIBeenRansom, Breach House
[!] Results are incomplete; inspect errors and truncation in the report
[*] Listings are unconfirmed exposure metadata, not a safety or maliciousness verdict
[+] DarkEye report saved to <local loot path>
```

### HaveIBeenRansom with an empty result

1. In the same module instance, set `DOMAIN` to `darkeye-smoke-nonexistent-xyz.com`.
1. Keep the valid `HIBR_API_KEY` and clear `BREACHHOUSE_API_KEY` by setting its datastore value to `nil`.
1. Keep the same request limits and run the module again.
1. Inspect the saved JSON report locally.

The report contained zero listings, with `products=["HaveIBeenRansom"]`,
`status=complete`, `truncated=false` and no product errors. This was a successful
empty response, not a failed lookup. It does not establish that a domain is safe.

```text
[*] LIVE B: HIBR only, empty-domain lookup
[*] DarkEye: 0 listing(s); status=complete; products=HaveIBeenRansom
[*] Listings are unconfirmed exposure metadata, not a safety or maliciousness verdict
[+] DarkEye report saved to <local loot path>
```

### Invalid HaveIBeenRansom key with a valid Breach House key

1. Set `DOMAIN` back to `example.com` in the same module instance.
1. Set `HIBR_API_KEY` to the intentionally invalid value `synthetic-invalid-key` and restore the valid `BREACHHOUSE_API_KEY` privately.
1. Keep the same request limits and run the module again.
1. Inspect the saved JSON report for the HaveIBeenRansom error and retained Breach House listings.

HaveIBeenRansom returned HTTP 401. The report retained three Breach House listings,
with `status=partial` and `truncated=false`, and recorded the HaveIBeenRansom error
separately. The failed product was not reported as an empty successful result.

```text
[*] LIVE C: invalid HIBR key, valid Breach House key
[!] HaveIBeenRansom: API returned HTTP 401
[*] DarkEye: 3 listing(s); status=partial; products=Breach House
[!] Results are incomplete; inspect errors and truncation in the report
[*] Listings are unconfirmed exposure metadata, not a safety or maliciousness verdict
[+] DarkEye report saved to <local loot path>
```
