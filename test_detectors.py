import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ninja_hunter.detectors import extract_sensitive, detect_exposure, check_security_headers


class TestExtractSensitive(unittest.TestCase):
    def test_finds_aws_key(self):
        body = '{"config": "AKIAABCDEFGHIJKLMNOP"}'
        findings = extract_sensitive(body)
        types = [f['type'] for f in findings]
        self.assertIn("AWS Access Key", types)

    def test_finds_jwt(self):
        body = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dBjftJeZ4CVP-mB92K"
        findings = extract_sensitive(body)
        types = [f['type'] for f in findings]
        self.assertIn("JWT Token", types)

    def test_clean_body_has_no_findings(self):
        body = '{"status": "ok", "message": "hello world"}'
        self.assertEqual(extract_sensitive(body), [])


class TestDetectExposure(unittest.TestCase):
    def test_git_head_real_hit(self):
        findings = detect_exposure(
            "https://x.com/.git/HEAD", 200, "text/plain", "ref: refs/heads/main\n"
        )
        self.assertTrue(any(f['type'] == "Exposed .git/HEAD" for f in findings))

    def test_git_head_wrong_content_no_hit(self):
        # Path matches but body doesn't look like a real git HEAD file —
        # should NOT fire, to avoid false positives on custom 404 pages.
        findings = detect_exposure(
            "https://x.com/.git/HEAD", 200, "text/html", "<html>Not Found</html>"
        )
        self.assertFalse(any(f['type'] == "Exposed .git/HEAD" for f in findings))

    def test_env_file_hit(self):
        findings = detect_exposure(
            "https://x.com/.env", 200, "text/plain", "DB_PASSWORD=hunter2\nAPI_KEY=abc\n"
        )
        self.assertTrue(any(f['type'] == "Exposed .env file" for f in findings))

    def test_swagger_schema_hit(self):
        findings = detect_exposure(
            "https://x.com/swagger.json", 200, "application/json",
            '{"swagger": "2.0", "paths": {}}'
        )
        self.assertTrue(any("Swagger" in f['type'] for f in findings))

    def test_stack_trace_hit(self):
        findings = detect_exposure(
            "https://x.com/debug", 200, "text/plain",
            "Traceback (most recent call last):\n  File x.py, line 1"
        )
        self.assertTrue(any(f['type'] == "Verbose stack trace in response" for f in findings))

    def test_non_200_never_fires(self):
        findings = detect_exposure(
            "https://x.com/.env", 404, "text/plain", "DB_PASSWORD=hunter2"
        )
        self.assertEqual(findings, [])


class TestSecurityHeaders(unittest.TestCase):
    def test_flags_missing_headers(self):
        findings = check_security_headers({"Content-Type": "text/html"})
        types = [f['type'] for f in findings]
        self.assertIn("Missing header: X-Frame-Options", types)

    def test_no_flags_when_all_present(self):
        headers = {
            "Strict-Transport-Security": "max-age=63072000",
            "X-Content-Type-Options": "nosniff",
            "X-Frame-Options": "DENY",
            "Content-Security-Policy": "default-src 'self'",
        }
        self.assertEqual(check_security_headers(headers), [])


if __name__ == '__main__':
    unittest.main()
