"""Startup checks optional package presence without importing its implementation."""
import ast
import importlib.util
import logging
import pathlib
import sys
import unittest
from unittest.mock import patch

ROOT = pathlib.Path(__file__).resolve().parent.parent


class DependencyChecks(unittest.TestCase):
    def setUp(self):
        tree = ast.parse((ROOT / 'main.py').read_text())
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
                        and n.name == '_check_dependencies')
        namespace = {'importlib': __import__('importlib'),
                     'logger': logging.getLogger('dependency-fixture')}
        exec(compile(ast.Module(body=[function], type_ignores=[]),
                     str(ROOT / 'main.py'), 'exec'), namespace)
        self.check = namespace['_check_dependencies']
        self.imports = []
        self.lookups = []

    def importer(self, name, *args, **kwargs):
        self.imports.append(name)
        return object()

    def finder(self, name):
        self.lookups.append(name)
        return object()

    def test_optional_packages_are_not_imported(self):
        with patch('builtins.__import__', self.importer), patch.object(
                importlib.util, 'find_spec', self.finder):
            self.assertTrue(self.check())
        self.assertEqual(self.imports, ['flask', 'flask_cors', 'sqlite3', 'psutil'])
        self.assertEqual(set(self.lookups), {
            'httpx', 'requests', 'paramiko', 'cryptography', 'scapy', 'maxminddb'})

    def test_missing_optional_packages_do_not_prevent_dashboard_start(self):
        with patch('builtins.__import__', self.importer), patch.object(
                importlib.util, 'find_spec', return_value=None):
            self.assertTrue(self.check())

    def test_missing_required_package_prevents_start(self):
        def broken(name, *args, **kwargs):
            if name == 'flask':
                raise ImportError('fixture missing package')
            return object()
        with patch('builtins.__import__', broken), patch.object(
                importlib.util, 'find_spec', self.finder):
            self.assertFalse(self.check())

    def test_invalid_optional_spec_is_reported_without_crashing(self):
        with patch('builtins.__import__', self.importer), patch.object(
                importlib.util, 'find_spec', side_effect=ValueError('bad spec')):
            self.assertTrue(self.check())


if __name__ == '__main__':
    unittest.main()
