#!/usr/bin/env python3
"""Test for the handle parsing fix in domains without top-level handles."""

import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '.'))

from whoisit.parser import ParseDomain
from whoisit.bootstrap import _BootstrapMainModule

def test_domain_handle_in_entities():
    """Test that handles can be found in entities when not at top level."""
    
    # Mock RDAP response similar to applegater.org - no top-level handle
    raw_data = {
        'ldhName': 'applegater.org',
        'unicodeName': 'applegater.org',
        'objectClassName': 'domain',
        'status': ['client transfer prohibited', 'client update prohibited'],
        'events': [
            {'eventAction': 'expiration', 'eventDate': '2026-04-02T17:16:10.748Z'},
            {'eventAction': 'registration', 'eventDate': '2008-04-02T17:16:10Z'},
            {'eventAction': 'last changed', 'eventDate': '2025-03-18T14:01:05Z'}
        ],
        'nameservers': [
            {'objectClassName': 'nameserver', 'ldhName': 'ns1.startlogic.com'},
            {'objectClassName': 'nameserver', 'ldhName': 'ns2.startlogic.com'}
        ],
        'entities': [
            {
                'objectClassName': 'entity',
                'handle': '69',
                'roles': ['registrar'],
                'publicIds': [{'type': 'IANA Registrar ID', 'identifier': '69'}]
            }
        ]
    }
    
    bootstrap = _BootstrapMainModule()
    parser = ParseDomain(bootstrap, raw_data, 'applegater.org', using_overrides=False)
    result = parser.parse()
    
    # The fix should find the handle in the entities section
    assert result['handle'] == '69', f"Expected handle '69', got '{result.get('handle')}'"
    assert result['name'] == 'applegater.org'
    assert result['status'] == ['client transfer prohibited', 'client update prohibited']
    assert len(result['nameservers']) == 2
    assert 'ns1.startlogic.com' in result['nameservers']
    assert 'ns2.startlogic.com' in result['nameservers']
    
    print("✓ Test passed: Handle found in entities when missing from top level")

def test_domain_handle_top_level_still_works():
    """Test that normal domains with top-level handles still work."""
    
    # Normal RDAP response with top-level handle
    raw_data = {
        'handle': '12345',
        'ldhName': 'example.com',
        'objectClassName': 'domain',
        'status': ['ok'],
        'events': [
            {'eventAction': 'expiration', 'eventDate': '2025-08-01T00:00:00Z'}
        ],
        'nameservers': [
            {'objectClassName': 'nameserver', 'ldhName': 'ns1.example.com'}
        ],
        'entities': [
            {
                'objectClassName': 'entity',
                'handle': '999',
                'roles': ['registrar']
            }
        ]
    }
    
    bootstrap = _BootstrapMainModule()
    parser = ParseDomain(bootstrap, raw_data, 'example.com', using_overrides=False)
    result = parser.parse()
    
    # Should prefer the top-level handle
    assert result['handle'] == '12345', f"Expected handle '12345', got '{result.get('handle')}'"
    assert result['name'] == 'example.com'
    
    print("✓ Test passed: Top-level handles still work correctly")

def test_domain_no_handle_anywhere():
    """Test domain with no handle anywhere - should still raise ParseError."""
    
    # RDAP response with no handle at all
    raw_data = {
        'ldhName': 'test.com',
        'objectClassName': 'domain',
        'status': ['ok'],
        'events': [
            {'eventAction': 'expiration', 'eventDate': '2025-08-01T00:00:00Z'}
        ],
        'nameservers': [
            {'objectClassName': 'nameserver', 'ldhName': 'ns1.test.com'}
        ]
        # No entities section either
    }
    
    bootstrap = _BootstrapMainModule()
    
    # Should still raise ParseError when no handle found anywhere
    try:
        parser = ParseDomain(bootstrap, raw_data, 'test.com', using_overrides=False)
        result = parser.parse()
        assert False, "Expected ParseError but parsing succeeded"
    except Exception as e:
        assert "Failed to parse any meaningful data to find a handle" in str(e)
    
    print("✓ Test passed: No handle case still raises ParseError as expected")

if __name__ == '__main__':
    test_domain_handle_in_entities()
    test_domain_handle_top_level_still_works()
    test_domain_no_handle_anywhere()
    print("\n✓ All handle parsing tests passed!")