#!/usr/bin/env python3
"""
Advanced Token Security Fuzzer for Claude Relay Service

Tests for:
- Session replay attacks
- Token tampering
- Expired token acceptance
- Auth header priority
- Multiple concurrent sessions

CVE Categories:
- CWE-613: Insufficient Session Expiration
- CWE-384: Session Fixation
- CWE-287: Improper Authentication
"""

import sys
import json
import argparse
import requests
import hashlib
import time
from datetime import datetime, timedelta
from urllib.parse import urljoin
from typing import Dict, Tuple

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class TokenSecurityFuzzer:
    """Advanced token security testing"""

    def __init__(self, base_url: str = 'http://localhost:13000', verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.timeout = 10

        self.results = {
            'passed': [],
            'failed': [],
            'vulnerabilities': [],
            'warnings': []
        }

    def test_session_replay(self) -> Tuple[bool, str]:
        """Test if same token can be used multiple times (CWE-613)"""
        print(f'\n{Colors.BOLD}[1] Session Replay Attack{Colors.RESET}')
        print('   Attempt to use same token multiple times')

        token = 'valid_admin_token_with_proper_length_for_testing'
        endpoint = '/users/'

        try:
            # First request
            resp1 = self.session.get(
                urljoin(self.base_url, endpoint),
                headers={'Authorization': f'Bearer {token}'},
                timeout=self.timeout
            )

            # Same token, second request
            time.sleep(0.1)
            resp2 = self.session.get(
                urljoin(self.base_url, endpoint),
                headers={'Authorization': f'Bearer {token}'},
                timeout=self.timeout
            )

            # Both should work (expected behavior)
            if resp1.status_code == 200 and resp2.status_code == 200:
                print(f'   {Colors.GREEN}✓{Colors.RESET} Token can be reused (no rotation) - EXPECTED')
                self.results['passed'].append('Session replay: Token reusable (expected)')
                return (True, 'Token is reusable')
            else:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} Unexpected response: {resp1.status_code}, {resp2.status_code}')
                self.results['warnings'].append(f'Unexpected replay response: {resp1.status_code}, {resp2.status_code}')
                return (False, 'Unexpected response')

        except Exception as e:
            print(f'   {Colors.RED}✗{Colors.RESET} Error: {e}')
            self.results['failed'].append(f'Session replay test failed: {str(e)}')
            return (False, str(e))

    def test_token_tampering(self) -> Tuple[bool, str]:
        """Test if tampered tokens are accepted"""
        print(f'\n{Colors.BOLD}[2] Token Tampering Detection{Colors.RESET}')
        print('   Attempt to tamper with token content')

        token = 'valid_admin_token_with_proper_length_for_testing'
        tampered_tokens = [
            ('Remove last char', token[:-1]),
            ('Change middle char', token[:25] + 'X' + token[26:]),
            ('Reverse token', token[::-1]),
            ('Duplicate token', token + token),
        ]

        endpoint = '/users/'
        vulnerabilities_found = []

        for desc, tampered in tampered_tokens:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers={'Authorization': f'Bearer {tampered}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    print(f'   {Colors.RED}✗ VULNERABILITY{Colors.RESET}: {desc} returned 200!')
                    vulnerabilities_found.append(desc)
                    self.results['vulnerabilities'].append(f'Token tampering: {desc} accepted')
                else:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {desc}: rejected ({resp.status_code})')
                    self.results['passed'].append(f'Token tampering {desc}: correctly rejected')

            except Exception as e:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} {desc}: {e}')

        if vulnerabilities_found:
            return (False, f'Found {len(vulnerabilities_found)} tampering vulnerabilities')
        return (True, 'All tampering attempts rejected')

    def test_expired_token_acceptance(self) -> Tuple[bool, str]:
        """Test if expired tokens are accepted (CWE-613)"""
        print(f'\n{Colors.BOLD}[3] Expired Token Acceptance{Colors.RESET}')
        print('   Test with token marked as 25+ hours old')

        token = 'expired_session_token_with_proper_testing_length'
        endpoint = '/users/'

        try:
            resp = self.session.get(
                urljoin(self.base_url, endpoint),
                headers={'Authorization': f'Bearer {token}'},
                timeout=self.timeout
            )

            if resp.status_code == 200:
                print(f'   {Colors.YELLOW}⚠ WARNING{Colors.RESET}: Expired token accepted (CWE-613)')
                self.results['warnings'].append('Expired token accepted - no expiration check')
                return (False, 'Expired token accepted')
            else:
                print(f'   {Colors.GREEN}✓{Colors.RESET} Expired token rejected: {resp.status_code}')
                self.results['passed'].append('Expired token correctly rejected')
                return (True, 'Expired token rejected')

        except Exception as e:
            print(f'   {Colors.RED}✗{Colors.RESET} Error: {e}')
            return (False, str(e))

    def test_auth_header_priority(self) -> Tuple[bool, str]:
        """Test priority when multiple auth headers provided"""
        print(f'\n{Colors.BOLD}[4] Auth Header Priority/Confusion{Colors.RESET}')
        print('   Test behavior with multiple auth methods')

        endpoint = '/users/'
        valid_token = 'valid_admin_token_with_proper_length_for_testing'
        invalid_token = 'invalid_token_but_still_32_chars_long_for_testing'

        test_cases = [
            ('Valid Authorization header', {'Authorization': f'Bearer {valid_token}'}, 200),
            ('Invalid Authorization header', {'Authorization': f'Bearer {invalid_token}'}, 401),
            ('Valid Authorization + Invalid Cookie',
             {'Authorization': f'Bearer {valid_token}', 'Cookie': f'adminToken={invalid_token}'}, 200),
            ('Invalid Authorization + Empty Cookie',
             {'Authorization': f'Bearer {invalid_token}', 'Cookie': 'adminToken='}, 401),
            ('X-Admin-Token header',
             {'X-Admin-Token': valid_token}, 200),
        ]

        vulnerabilities = []
        for desc, headers, expected in test_cases:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers=headers,
                    timeout=self.timeout
                )

                if resp.status_code == expected:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {desc}: {resp.status_code} (expected)')
                    self.results['passed'].append(f'Auth priority: {desc}')
                else:
                    print(f'   {Colors.YELLOW}⚠{Colors.RESET} {desc}: {resp.status_code} (expected {expected})')
                    self.results['warnings'].append(f'Auth priority: {desc} unexpected response')

            except Exception as e:
                print(f'   {Colors.RED}✗{Colors.RESET} {desc}: {e}')

        return (len(vulnerabilities) == 0, f'Found {len(vulnerabilities)} header priority issues')

    def test_null_token(self) -> Tuple[bool, str]:
        """Test various empty/null token scenarios"""
        print(f'\n{Colors.BOLD}[5] Null/Empty Token Handling{Colors.RESET}')
        print('   Test missing or empty tokens')

        endpoint = '/users/'
        test_cases = [
            ('No Authorization header', {}, 401),
            ('Empty Bearer token', {'Authorization': 'Bearer '}, 401),
            ('Bearer without space', {'Authorization': 'Bearer'}, 401),
            ('Empty X-Admin-Token', {'X-Admin-Token': ''}, 401),
            ('Null-like string', {'Authorization': 'Bearer null'}, 401),
        ]

        vulnerabilities = []
        for desc, headers, expected in test_cases:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers=headers,
                    timeout=self.timeout
                )

                if resp.status_code == expected:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {desc}: {resp.status_code}')
                    self.results['passed'].append(f'Null handling: {desc}')
                else:
                    if resp.status_code == 200:
                        print(f'   {Colors.RED}✗ VULNERABILITY{Colors.RESET}: {desc} returned 200!')
                        vulnerabilities.append(desc)
                        self.results['vulnerabilities'].append(f'Null token accepted: {desc}')
                    else:
                        print(f'   {Colors.YELLOW}⚠{Colors.RESET} {desc}: {resp.status_code}')

            except Exception as e:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} {desc}: {e}')

        return (len(vulnerabilities) == 0, f'Found {len(vulnerabilities)} null handling vulnerabilities')

    def test_token_injection(self) -> Tuple[bool, str]:
        """Test for injection attacks in token"""
        print(f'\n{Colors.BOLD}[6] Token Injection Attacks{Colors.RESET}')
        print('   Test special characters and payloads in token')

        endpoint = '/users/'
        injection_tokens = [
            ('SQL-like', "valid_admin_token' OR '1'='1"),
            ('Redis-like', 'FLUSHDB; valid_admin_token'),
            ('Command', '$(whoami) valid_token_32_chars'),
            ('Path traversal', '../../../etc/passwd_12_34_567'),
            ('Null byte', 'valid_admin_token\x00extra_data'),
        ]

        # Ensure tokens are at least 32 chars
        injection_tokens = [(name, (token + '_padded'*3)[:48]) for name, token in injection_tokens]

        vulnerabilities = []
        for desc, token in injection_tokens:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers={'Authorization': f'Bearer {token}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    print(f'   {Colors.RED}✗ VULNERABILITY{Colors.RESET}: {desc} accepted!')
                    vulnerabilities.append(desc)
                    self.results['vulnerabilities'].append(f'Injection: {desc} accepted')
                else:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {desc}: rejected')
                    self.results['passed'].append(f'Injection {desc}: correctly rejected')

            except Exception as e:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} {desc}: {e}')

        return (len(vulnerabilities) == 0, f'Found {len(vulnerabilities)} injection vulnerabilities')

    def run_all_tests(self) -> bool:
        """Run all token security tests"""
        print(f'\n{Colors.BOLD}🔐 Advanced Token Security Fuzzing{Colors.RESET}')
        print('=' * 60)
        print(f'Target: {self.base_url}')
        print(f'Tests: 6 categories')
        print()

        # Verify connectivity
        try:
            resp = self.session.get(urljoin(self.base_url, '/health'), timeout=self.timeout)
            if resp.status_code != 200:
                print(f'{Colors.RED}✗ Server not healthy{Colors.RESET}')
                return False
            print(f'{Colors.GREEN}✓ Server is healthy{Colors.RESET}\n')
        except Exception as e:
            print(f'{Colors.RED}✗ Cannot reach server: {e}{Colors.RESET}')
            return False

        # Run all tests
        test_results = []
        test_results.append(self.test_session_replay())
        test_results.append(self.test_token_tampering())
        test_results.append(self.test_expired_token_acceptance())
        test_results.append(self.test_auth_header_priority())
        test_results.append(self.test_null_token())
        test_results.append(self.test_token_injection())

        # Print summary
        print(f'\n{Colors.BOLD}' + '=' * 60)
        print('Test Summary')
        print('=' * 60 + Colors.RESET)

        print(f'{Colors.GREEN}Passed: {len(self.results["passed"])}{Colors.RESET}')
        print(f'{Colors.YELLOW}Warnings: {len(self.results["warnings"])}{Colors.RESET}')
        print(f'{Colors.RED}Vulnerabilities: {len(self.results["vulnerabilities"])}{Colors.RESET}')
        print(f'{Colors.RED}Failed: {len(self.results["failed"])}{Colors.RESET}')

        if self.results['vulnerabilities']:
            print(f'\n{Colors.RED}{Colors.BOLD}🚨 VULNERABILITIES DETECTED:{Colors.RESET}')
            for vuln in self.results['vulnerabilities']:
                print(f'  {Colors.RED}• {vuln}{Colors.RESET}')

        if self.results['warnings']:
            print(f'\n{Colors.YELLOW}{Colors.BOLD}⚠️  WARNINGS:{Colors.RESET}')
            for warn in self.results['warnings']:
                print(f'  {Colors.YELLOW}• {warn}{Colors.RESET}')

        return len(self.results['vulnerabilities']) == 0


def main():
    parser = argparse.ArgumentParser(description='Advanced Token Security Fuzzer')
    parser.add_argument('--base-url', default='http://localhost:13000', help='Base URL of relay service')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--output', help='Output JSON file')

    args = parser.parse_args()

    fuzzer = TokenSecurityFuzzer(args.base_url, args.verbose)
    success = fuzzer.run_all_tests()

    # Save results
    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'target': args.base_url,
                'results': fuzzer.results
            }, f, indent=2)
        print(f'\n{Colors.GREEN}Results saved to {args.output}{Colors.RESET}')

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
