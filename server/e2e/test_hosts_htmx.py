"""Browser E2E tests for the HTMX hosts view (runtime behaviour under strict CSP)."""


def _csp(errors):
    # A genuine CSP violation always names the policy ("...Content Security Policy
    # directive..."). We deliberately do NOT match a bare "Refused to", which also
    # covers an unrelated strict-MIME rejection of theme.css — that file is a
    # Tailwind build artifact (gitignored) and is simply absent in a bare checkout.
    return [e for e in errors if "Content Security Policy" in e]


def test_htmx_and_app_js_run_under_csp(page, live_server, console_errors):
    page.goto(f"{live_server}/hosts", wait_until="load")
    # External scripts actually executed despite script-src 'self'
    assert page.evaluate("typeof window.htmx !== 'undefined'")
    assert page.locator("#hostTable").count() == 1
    assert page.get_by_text("smoke-host").count() >= 1
    assert _csp(console_errors) == [], console_errors


def test_collect_button_triggers_htmx_post(page, live_server):
    page.goto(f"{live_server}/hosts", wait_until="load")
    with page.expect_response(
        lambda r: "/hosts/collect" in r.url and r.request.method == "POST"
    ) as info:
        page.locator("button", has_text="Collect now").click()
    assert info.value.status == 200          # CSRF header accepted by the server
    page.wait_for_timeout(200)
    assert page.url.rstrip("/").endswith("/hosts")   # swapped, not a full navigation
    assert page.locator("#hostTable").count() == 1


def test_scan_button_triggers_htmx_post(page, live_server):
    # "Scan now" on the Images page enqueues Trivy+Xeol via an htmx POST and swaps
    # the table in place (no full navigation).
    page.goto(f"{live_server}/images", wait_until="load")
    with page.expect_response(
        lambda r: "/images/scan" in r.url and r.request.method == "POST"
    ) as info:
        page.locator("button", has_text="Scan now").click()
    assert info.value.status == 200          # CSRF header accepted by the server
    page.wait_for_timeout(200)
    assert page.url.rstrip("/").endswith("/images")
    assert page.locator("#imagesTable").count() == 1


def test_vulnerability_filter_by_cve(page, live_server):
    # Typing a CVE live-filters the table via htmx (keyup -> GET /vulnerabilities/table).
    page.goto(f"{live_server}/vulnerabilities", wait_until="load")
    assert page.locator('#vulnTable tr', has_text="CVE-2026-111111").count() == 1
    assert page.locator('#vulnTable tr', has_text="CVE-2026-222222").count() == 1
    with page.expect_response(lambda r: "/vulnerabilities/table" in r.url and r.request.method == "GET"):
        page.locator("#cve").press_sequentially("111111")
    page.wait_for_timeout(300)
    assert page.locator('#vulnTable tr', has_text="CVE-2026-111111").count() == 1
    assert page.locator('#vulnTable tr', has_text="CVE-2026-222222").count() == 0


def test_vulnerability_filter_by_min_severity(page, live_server):
    page.goto(f"{live_server}/vulnerabilities", wait_until="load")
    with page.expect_response(lambda r: "/vulnerabilities/table" in r.url):
        page.locator("#severity").select_option("CRITICAL")
    page.wait_for_timeout(300)
    assert page.locator('#vulnTable tr', has_text="CVE-2026-111111").count() == 1   # CRITICAL stays
    assert page.locator('#vulnTable tr', has_text="CVE-2026-222222").count() == 0   # LOW filtered out


def test_table_partial_swap(page, live_server):
    # Same mechanism the 60s poll uses: hx-get /hosts/table, outerHTML swap.
    page.goto(f"{live_server}/hosts", wait_until="load")
    with page.expect_response(
        lambda r: "/hosts/table" in r.url and r.request.method == "GET"
    ) as info:
        page.evaluate("window.htmx.ajax('GET','/hosts/table',{target:'#hostTable',swap:'outerHTML'})")
    assert info.value.status == 200
    assert page.locator("#hostTable").count() == 1


def test_row_data_href_navigation(page, live_server):
    page.goto(f"{live_server}/hosts", wait_until="load")
    page.locator("#hostTable tbody tr[data-href]").first.locator("td").first.click()
    page.wait_for_load_state("load")
    assert "/hosts/" in page.url and not page.url.rstrip("/").endswith("/hosts")


def test_edit_button_does_not_trigger_row_nav(page, live_server):
    # Regression for the fixed click-race: Edit must win over the row's data-href.
    page.goto(f"{live_server}/hosts", wait_until="load")
    page.locator('#hostTable tbody a', has_text="Edit").first.click()
    page.wait_for_load_state("load")
    assert "/hosts/edit/" in page.url


def test_header_sort_runs_without_errors(page, live_server, console_errors):
    page.goto(f"{live_server}/hosts", wait_until="load")
    page.locator("#hostTable thead th").first.click()
    assert _csp(console_errors) == [], console_errors
