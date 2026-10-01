import sys
import os
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from ninja_hunter.discovery import (
    parse_robots_txt,
    parse_sitemap_xml,
    extract_paths_from_openapi,
    extract_links_from_body,
)


class TestRobotsTxt(unittest.TestCase):
    def test_extracts_disallow_paths(self):
        text = "User-agent: *\nDisallow: /admin\nDisallow: /internal/api\nAllow: /public\n"
        paths = parse_robots_txt(text)
        self.assertIn("admin", paths)
        self.assertIn("internal/api", paths)
        self.assertIn("public", paths)

    def test_ignores_bare_slash(self):
        text = "Disallow: /\n"
        self.assertEqual(parse_robots_txt(text), [])

    def test_dedupes(self):
        text = "Disallow: /admin\nDisallow: /admin\n"
        self.assertEqual(parse_robots_txt(text), ["admin"])


class TestSitemap(unittest.TestCase):
    def test_extracts_locs(self):
        xml = (
            "<urlset><url><loc>https://x.com/a</loc></url>"
            "<url><loc>https://x.com/b</loc></url></urlset>"
        )
        self.assertEqual(parse_sitemap_xml(xml), ["https://x.com/a", "https://x.com/b"])


class TestOpenAPI(unittest.TestCase):
    def test_extracts_paths(self):
        doc = '{"openapi": "3.0.0", "paths": {"/users": {}, "/users/{id}": {}}}'
        paths = extract_paths_from_openapi(doc)
        self.assertIn("users", paths)
        self.assertIn("users/{id}", paths)

    def test_handles_base_path(self):
        doc = '{"swagger": "2.0", "basePath": "/api/v1", "paths": {"/users": {}}}'
        paths = extract_paths_from_openapi(doc)
        self.assertIn("api/v1/users", paths)

    def test_invalid_json_returns_empty(self):
        self.assertEqual(extract_paths_from_openapi("not json"), [])

    def test_non_openapi_json_returns_empty(self):
        self.assertEqual(extract_paths_from_openapi('{"hello": "world"}'), [])


class TestExtractLinks(unittest.TestCase):
    def test_finds_json_string_paths(self):
        body = '{"next": "/api/v2/users", "self": "/api/v2/users/1"}'
        links = extract_links_from_body(body, "application/json", "https://x.com")
        self.assertIn("https://x.com/api/v2/users", links)

    def test_finds_html_hrefs(self):
        body = '<a href="/docs">Docs</a><img src="/static/x.png">'
        links = extract_links_from_body(body, "text/html", "https://x.com")
        self.assertIn("https://x.com/docs", links)

    def test_drops_offsite_links(self):
        body = '<a href="https://evil.example.com/x">ext</a>'
        links = extract_links_from_body(body, "text/html", "https://x.com")
        self.assertEqual(links, set())


if __name__ == '__main__':
    unittest.main()
