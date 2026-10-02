"""
Ninja-API-Hunter v4.0
Unit tests for regex signatures, helper functions, and each detection
module's pure logic. None of these tests touch the network.
"""
import asyncio
import os
import re
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ninja_hunter.config import SENSITIVE_PATTERNS, SWAGGER_PATHS, SECURITY_HEADERS
from ninja_hunter.core.rate_limiter import AdaptiveRateLimiter
from ninja_hunter.modules.swagger import SwaggerDiscovery
from ninja_hunter.modules.discovery import PassiveDiscovery
from ninja_hunter.modules.cors import CORSDetector
from ninja_hunter.modules.bola import BOLADetector
from ninja_hunter.modules.exposures import ExposureScanner
from ninja_hunter.utils.helpers import parse_headers, classify


class TestConfigPatterns(unittest.TestCase):
    def test_all_sensitive_patterns_compile(self):
        for vuln_type, patterns in SENSITIVE_PATTERNS.items():
            for pattern in patterns:
                try:
                    re.compile(pattern)
                except re.error as e:
                    self.fail(f"{vuln_type} pattern failed to compile: {e}")

    def test_jwt_pattern_matches_sample(self):
        sample = "token=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
        self.assertIsNotNone(re.search(SENSITIVE_PATTERNS["JWT Token"][0], sample))

    def test_aws_key_pattern_matches_sample(self):
        sample = "AKIAABCDEFGHIJKLMNOP"
        self.assertIsNotNone(re.search(SENSITIVE_PATTERNS["AWS Access Key"][0], sample))

    def test_swagger_paths_not_empty(self):
        self.assertGreater(len(SWAGGER_PATHS), 0)

    def test_security_headers_list_not_empty(self):
        self.assertGreater(len(SECURITY_HEADERS), 0)


class TestRateLimiter(unittest.TestCase):
    def test_backoff_increases_delay_on_429(self):
        rl = AdaptiveRateLimiter(base_delay=0.0, max_delay=2.0)
        before = rl.current_delay
        rl.record(429)
        self.assertGreater(rl.current_delay, before)

    def test_delay_capped_at_max(self):
        rl = AdaptiveRateLimiter(base_delay=0.0, max_delay=1.0, backoff_factor=10)
        for _ in range(5):
            rl.record(503)
        self.assertLessEqual(rl.current_delay, 1.0)

    def test_recovers_after_success(self):
        rl = AdaptiveRateLimiter(base_delay=0.0, max_delay=2.0)
        rl.record(429)
        rl.record(429)
        peak = rl.current_delay
        rl.record(200)
        self.assertLess(rl.current_delay, peak)


class TestSwaggerModule(unittest.TestCase):
    def test_parse_json_body(self):
        parsed = SwaggerDiscovery._parse('{"paths": {"/x": {}}}')
        self.assertIsInstance(parsed, dict)

    def test_parse_empty_body_returns_none(self):
        self.assertIsNone(SwaggerDiscovery._parse(""))

    def test_extract_endpoints_methods_and_params(self):
        spec = {
            "paths": {
                "/users/{id}": {
                    "get": {"summary": "Get user", "parameters": [{"name": "id"}]},
                    "delete": {"summary": "Delete user"},
                }
            }
        }
        endpoints = SwaggerDiscovery.extract_endpoints(spec, "https://api.test.com")
        methods = sorted(e["method"] for e in endpoints)
        self.assertEqual(methods, ["DELETE", "GET"])

    def test_extract_endpoints_empty_spec(self):
        self.assertEqual(SwaggerDiscovery.extract_endpoints({}, "https://x.com"), [])


class DummyEngine:
    """Minimal stand-in for RequestEngine so module logic can be
    tested without performing real network requests."""
    def __init__(self, response):
        self._response = response

    async def request(self, *args, **kwargs):
        return self._response


class SequencedEngine:
    """Like DummyEngine, but returns a different response each call, in
    order -- used for modules that make more than one request."""
    def __init__(self, responses):
        self._responses = list(responses)

    async def request(self, *args, **kwargs):
        return self._responses.pop(0)


class TestCORSModule(unittest.TestCase):
    def test_flags_reflected_origin_with_credentials(self):
        engine = DummyEngine({
            "status": 200,
            "headers": {
                "Access-Control-Allow-Origin": "https://evil.com",
                "Access-Control-Allow-Credentials": "true",
            },
        })
        result = asyncio.run(CORSDetector(engine).test_endpoint("https://api.test.com/data"))
        self.assertTrue(result["flagged"])
        self.assertEqual(result["severity"], "high")

    def test_does_not_flag_strict_cors(self):
        engine = DummyEngine({
            "status": 200,
            "headers": {"Access-Control-Allow-Origin": "https://trusted.com"},
        })
        result = asyncio.run(CORSDetector(engine).test_endpoint("https://api.test.com/data"))
        self.assertFalse(result["flagged"])


class TestBOLAModule(unittest.TestCase):
    def test_similarity_identical_strings(self):
        self.assertEqual(BOLADetector._similarity("abcdef", "abcdef"), 1.0)

    def test_similarity_empty_string(self):
        self.assertEqual(BOLADetector._similarity("", "abc"), 0.0)

    def test_flags_when_both_tokens_get_200(self):
        engine = SequencedEngine([
            {"status": 200, "body": '{"user": "a"}', "headers": {}},
            {"status": 200, "body": '{"user": "b"}', "headers": {}},
        ])
        result = asyncio.run(
            BOLADetector(engine, "token-a", "token-b").test_endpoint("https://api.test.com/orders/1")
        )
        self.assertTrue(result["flagged"])

    def test_no_flag_when_second_token_denied(self):
        engine = SequencedEngine([
            {"status": 200, "body": '{"user": "a"}', "headers": {}},
            {"status": 403, "body": "", "headers": {}},
        ])
        result = asyncio.run(
            BOLADetector(engine, "token-a", "token-b").test_endpoint("https://api.test.com/orders/1")
        )
        self.assertFalse(result["flagged"])


class TestPassiveDiscoveryModule(unittest.TestCase):
    def test_parse_robots_txt_extracts_disallowed_paths(self):
        body = "User-agent: *\nDisallow: /admin\nDisallow: /\nAllow: /public\nSitemap: https://x.com/sitemap.xml"
        paths = PassiveDiscovery.parse_robots_txt(body)
        self.assertIn("/admin", paths)
        self.assertIn("/public", paths)
        self.assertNotIn("/", paths)

    def test_parse_sitemap_xml_extracts_locs(self):
        body = (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
            "<url><loc>https://api.test.com/a</loc></url>"
            "<url><loc>https://api.test.com/b</loc></url>"
            "</urlset>"
        )
        urls = PassiveDiscovery.parse_sitemap_xml(body)
        self.assertIn("https://api.test.com/a", urls)
        self.assertIn("https://api.test.com/b", urls)

    def test_parse_sitemap_xml_falls_back_on_malformed_xml(self):
        body = "<urlset><url><loc>https://api.test.com/c</loc></url"  # truncated/invalid
        urls = PassiveDiscovery.parse_sitemap_xml(body)
        self.assertIn("https://api.test.com/c", urls)

    def test_discover_all_filters_to_same_host(self):
        class RoutedEngine:
            async def request(self, method, url, **kwargs):
                if url.endswith("robots.txt"):
                    return {"status": 200, "body": "Disallow: /secret"}
                if url.endswith("sitemap.xml"):
                    return {
                        "status": 200,
                        "body": "<urlset><url><loc>https://other-host.com/x</loc></url></urlset>",
                    }
                return {"status": 404, "body": ""}

        result = asyncio.run(PassiveDiscovery(RoutedEngine()).discover_all("https://api.test.com"))
        self.assertIn("https://api.test.com/secret", result)
        self.assertNotIn("https://other-host.com/x", result)


class TestExposuresModule(unittest.TestCase):
    def test_scan_body_for_secrets_detects_jwt(self):
        body = "auth=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dGVzdHNpZ25hdHVyZQ"
        types = [f["type"] for f in ExposureScanner.scan_body_for_secrets(body)]
        self.assertIn("JWT Token", types)

    def test_scan_body_for_secrets_empty_body(self):
        self.assertEqual(ExposureScanner.scan_body_for_secrets(""), [])

    def test_stack_trace_detection(self):
        body = "Traceback (most recent call last):\n  File test.py"
        self.assertTrue(len(ExposureScanner.scan_body_for_stack_traces(body)) > 0)

    def test_missing_security_headers(self):
        missing = ExposureScanner.check_security_headers({"Content-Type": "text/html"})
        self.assertIn("X-Frame-Options", missing)

    def test_no_missing_headers_when_all_present(self):
        headers = {h: "1" for h in SECURITY_HEADERS}
        self.assertEqual(ExposureScanner.check_security_headers(headers), [])


class TestHelpers(unittest.TestCase):
    def test_parse_headers_basic(self):
        result = parse_headers(["Authorization: Bearer xyz", "X-Test: 1"])
        self.assertEqual(result["Authorization"], "Bearer xyz")
        self.assertEqual(result["X-Test"], "1")

    def test_parse_headers_ignores_malformed(self):
        self.assertEqual(parse_headers(["NoColonHere"]), {})

    def test_classify_statuses(self):
        self.assertEqual(classify(200), "ALIVE")
        self.assertEqual(classify(401), "PROTECTED")
        self.assertEqual(classify(301), "REDIRECT")
        self.assertEqual(classify(500), "DEAD")
        self.assertEqual(classify(None), "ERROR")


if __name__ == "__main__":
    unittest.main()
