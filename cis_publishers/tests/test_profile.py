"""
New tests for some old code.
"""
# pylint: disable=missing-docstring

import unittest
from unittest.mock import MagicMock

from cis_publishers.common.profile import SignableAttribute


def attribute_factory(current_value, key="values"):
    """
    A slim SignableAttribute factory. Skips signing, etc.
    """
    return SignableAttribute({key: current_value}, name="ldap", parent_profile=MagicMock())


class SignableAttributeListNormalizationTests(unittest.TestCase):
    def test_some_to_empty(self):
        attr = attribute_factory({"foo": None, "bar": None})
        attr.values = []
        self.assertEqual(attr.data["values"], {})

    def test_none_to_empty(self):
        attr = attribute_factory(None)
        attr.values = []
        self.assertIsNone(attr.data["values"])

    def test_some_to_less(self):
        attr = attribute_factory({"foo": None, "bar": None})
        attr.values = ["foo"]
        self.assertEqual(attr.data["values"], {"foo": None})


if __name__ == "__main__":
    unittest.main()
