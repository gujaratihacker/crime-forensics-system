import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from seed_data import get_seed_password
from scripts.build_netlify import build_netlify_redirects


class NetlifyRedirectBuildTests(unittest.TestCase):
    def test_builds_catch_all_proxy_for_https_backend(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            output_file = build_netlify_redirects(
                ' https://flask.example.com/ ',
                Path(temp_dir) / 'publish',
            )

            self.assertEqual(
                output_file.read_text(encoding='utf-8'),
                '/* https://flask.example.com/:splat 200!\n',
            )

    def test_rejects_backend_urls_that_are_not_https_origins(self):
        invalid_urls = (
            'http://flask.example.com',
            'https://user:password@flask.example.com',
            'https://flask.example.com/api',
            'https://flask.example.com?debug=true',
            'https://flask.example.com#section',
        )
        with tempfile.TemporaryDirectory() as temp_dir:
            output_dir = Path(temp_dir) / 'publish'
            for backend_url in invalid_urls:
                with self.subTest(backend_url=backend_url):
                    with self.assertRaises(ValueError):
                        build_netlify_redirects(backend_url, output_dir)

    def test_rejects_invalid_backend_port(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            with self.assertRaises(ValueError):
                build_netlify_redirects(
                    'https://flask.example.com:99999',
                    Path(temp_dir) / 'publish',
                )

    def test_seed_password_can_be_overridden_for_deployment(self):
        password = 'UniqueDeployment123'
        with patch.dict('os.environ', {'SEED_ADMIN_PASSWORD': password}):
            self.assertEqual(get_seed_password('SEED_ADMIN_PASSWORD', 'local-demo'), password)

    def test_seed_password_rejects_weak_deployment_override(self):
        with patch.dict('os.environ', {'SEED_ADMIN_PASSWORD': 'weak'}):
            with self.assertRaises(ValueError):
                get_seed_password('SEED_ADMIN_PASSWORD', 'local-demo')


if __name__ == '__main__':
    unittest.main()
