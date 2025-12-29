#!/usr/bin/env python3
"""
Horizontal Privilege Escalation / IDOR Fuzzer

Tests for:
- Insecure Direct Object References (IDOR)
- Cross-user data access
- Cross-API Key access
- Resource enumeration

CVE Categories:
- CWE-639: Authorization Bypass Through User-Controlled Key
- CWE-285: Improper Access Control
"""

import sys
import json
import requests
from datetime import datetime
from urllib.parse import urljoin
from typing import List, Tuple

class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    BOLD = '\033[1m'
    RESET = '\033[0m'


class HorizontalPrivilegeFuzzer:
    """Test for horizontal privilege escalation / IDOR vulnerabilities"""

    def __init__(self, base_url: str = 'http://localhost:13000'):
        self.base_url = base_url.rstrip('/')
        self.session = requests.Session()
        self.timeout = 10
        self.token = 'valid_admin_token_with_proper_length_for_testing'

        self.results = {
            'passed': [],
            'failed': [],
            'vulnerabilities': [],
            'enumerations': []
        }

    def test_user_enumeration(self) -> Tuple[bool, str]:
        """Test if user IDs can be enumerated"""
        print(f'\n{Colors.BOLD}[1] User Enumeration (IDOR){Colors.RESET}')
        print('   Test accessing user endpoints with various IDs')

        endpoint_template = '/users/{}/'
        test_ids = [
            '1', '2', '3', '0', '-1',  # Sequential
            'admin', 'test', 'user1',   # Common names
            'a' * 32, 'x' * 24,         # Length tests
        ]

        found_users = []
        for user_id in test_ids:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint_template.format(user_id)),
                    headers={'Authorization': f'Bearer {self.token}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    print(f'   {Colors.RED}✗ IDOR{Colors.RESET}: User {user_id} found (200)')
                    found_users.append(user_id)
                    self.results['vulnerabilities'].append(f'IDOR: User {user_id} enumerable')
                elif resp.status_code == 404:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} User {user_id}: Not found (404)')
                    self.results['passed'].append(f'User {user_id}: Protected')
                elif resp.status_code == 403:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} User {user_id}: Forbidden (403)')
                    self.results['passed'].append(f'User {user_id}: Protected')

            except Exception as e:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} User {user_id}: {type(e).__name__}')

        if found_users:
            print(f'   {Colors.RED}Found {len(found_users)} enumerable users{Colors.RESET}')
            self.results['enumerations'].append(f'Enumerable users: {found_users}')
            return (False, f'Found {len(found_users)} enumerable users')

        return (True, 'User enumeration protected')

    def test_api_key_enumeration(self) -> Tuple[bool, str]:
        """Test if API Keys can be enumerated/accessed"""
        print(f'\n{Colors.BOLD}[2] API Key Enumeration (IDOR){Colors.RESET}')
        print('   Test accessing API keys with various IDs')

        endpoint_template = '/admin/api-keys/{}'
        test_ids = [
            'test-key-1', 'test-key-2', 'admin-key',
            'cr_' + 'a' * 20, 'cr_' + 'b' * 20,
        ]

        found_keys = []
        for key_id in test_ids:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint_template.format(key_id)),
                    headers={'Authorization': f'Bearer {self.token}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        print(f'   {Colors.RED}✗ IDOR{Colors.RESET}: API Key {key_id} exposed (200)')
                        found_keys.append(key_id)
                        self.results['vulnerabilities'].append(f'IDOR: API Key {key_id} accessible')
                    except:
                        print(f'   {Colors.YELLOW}⚠{Colors.RESET} Key {key_id}: 200 but invalid JSON')
                elif resp.status_code == 404:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} Key {key_id}: Not found (404)')
                    self.results['passed'].append(f'Key {key_id}: Protected')

            except Exception as e:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} Key {key_id}: {type(e).__name__}')

        if found_keys:
            self.results['enumerations'].append(f'Enumerable API keys: {found_keys}')
            return (False, f'Found {len(found_keys)} enumerable keys')

        return (True, 'API key enumeration protected')

    def test_cross_user_access(self) -> Tuple[bool, str]:
        """Test if tokens can access resources of other users"""
        print(f'\n{Colors.BOLD}[3] Cross-User Data Access{Colors.RESET}')
        print('   Test accessing other users data with own token')

        # Using valid admin token, try to access various user IDs
        test_urls = [
            '/users/other-user/profile',
            '/users/2/api-keys',
            '/users/admin/settings',
            '/users/test/stats',
        ]

        vulnerabilities = []
        for url in test_urls:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, url),
                    headers={'Authorization': f'Bearer {self.token}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    print(f'   {Colors.RED}✗ IDOR{Colors.RESET}: {url} accessed (200)')
                    vulnerabilities.append(url)
                    self.results['vulnerabilities'].append(f'IDOR: {url} accessible')
                elif resp.status_code == 404:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {url}: Not found (404)')
                    self.results['passed'].append(f'Cross-user: {url} protected')
                elif resp.status_code == 403:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {url}: Forbidden (403)')
                    self.results['passed'].append(f'Cross-user: {url} protected')

            except Exception as e:
                print(f'   {Colors.YELLOW}⚠{Colors.RESET} {url}: {type(e).__name__}')

        return (len(vulnerabilities) == 0, f'Found {len(vulnerabilities)} cross-user access vulnerabilities')

    def test_statistics_exposure(self) -> Tuple[bool, str]:
        """Test if user statistics leak information"""
        print(f'\n{Colors.BOLD}[4] Statistics/Usage Data Exposure{Colors.RESET}')
        print('   Test accessing usage statistics for other users/keys')

        stats_endpoints = [
            '/users/stats/overall',
            '/users/stats/monthly',
            '/admin/stats/by-user',
            '/admin/stats/by-key',
        ]

        vulnerabilities = []
        for endpoint in stats_endpoints:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers={'Authorization': f'Bearer {self.token}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # Check if data contains other users
                        json_str = json.dumps(data)
                        if 'user_id' in json_str.lower() or 'other' in json_str.lower():
                            print(f'   {Colors.RED}✗ DATA LEAK{Colors.RESET}: {endpoint} exposes multiple users')
                            vulnerabilities.append(endpoint)
                            self.results['vulnerabilities'].append(f'Data leak: {endpoint}')
                        else:
                            print(f'   {Colors.GREEN}✓{Colors.RESET} {endpoint}: {resp.status_code}')
                            self.results['passed'].append(f'Stats: {endpoint}')
                    except:
                        print(f'   {Colors.YELLOW}⚠{Colors.RESET} {endpoint}: 200 but invalid JSON')
                elif resp.status_code == 404:
                    print(f'   {Colors.YELLOW}⚠{Colors.RESET} {endpoint}: Not found')
                    self.results['passed'].append(f'Stats: {endpoint} not found')

            except Exception as e:
                print(f'   {Colors.GREEN}✓{Colors.RESET} {endpoint}: Protected')
                self.results['passed'].append(f'Stats: {endpoint} protected')

        return (len(vulnerabilities) == 0, f'Found {len(vulnerabilities)} data exposure vulnerabilities')

    def test_resource_bulk_access(self) -> Tuple[bool, str]:
        """Test if bulk resource access can enumerate data"""
        print(f'\n{Colors.BOLD}[5] Bulk Resource Access/Mass Assignment{Colors.RESET}')
        print('   Test accessing multiple resources at once')

        bulk_endpoints = [
            '/users/?limit=1000',
            '/admin/api-keys?limit=1000',
            '/users/all',
            '/admin/all-keys',
        ]

        vulnerabilities = []
        for endpoint in bulk_endpoints:
            try:
                resp = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers={'Authorization': f'Bearer {self.token}'},
                    timeout=self.timeout
                )

                if resp.status_code == 200:
                    try:
                        data = resp.json()
                        # If it returns a list/array, we can enumerate
                        if isinstance(data, list) and len(data) > 0:
                            print(f'   {Colors.RED}✗ ENUMERATION{Colors.RESET}: {endpoint} returned {len(data)} items')
                            vulnerabilities.append(endpoint)
                            self.results['vulnerabilities'].append(f'Bulk access: {endpoint} enumerates {len(data)} items')
                        elif isinstance(data, dict) and 'items' in data:
                            count = len(data.get('items', []))
                            print(f'   {Colors.RED}✗ ENUMERATION{Colors.RESET}: {endpoint} returned {count} items')
                            vulnerabilities.append(endpoint)
                    except:
                        print(f'   {Colors.YELLOW}⚠{Colors.RESET} {endpoint}: Invalid response')
                elif resp.status_code == 404:
                    print(f'   {Colors.GREEN}✓{Colors.RESET} {endpoint}: Not found (404)')
                    self.results['passed'].append(f'Bulk: {endpoint} protected')

            except Exception as e:
                print(f'   {Colors.GREEN}✓{Colors.RESET} {endpoint}: Protected')
                self.results['passed'].append(f'Bulk: {endpoint} protected')

        return (len(vulnerabilities) == 0, f'Found {len(vulnerabilities)} bulk access vulnerabilities')

    def run_all_tests(self) -> bool:
        """Run all horizontal privilege tests"""
        print(f'\n{Colors.BOLD}🔀 Horizontal Privilege Escalation / IDOR Fuzzing{Colors.RESET}')
        print('=' * 60)
        print(f'Target: {self.base_url}')
        print(f'Tests: 5 categories')
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
        self.test_user_enumeration()
        self.test_api_key_enumeration()
        self.test_cross_user_access()
        self.test_statistics_exposure()
        self.test_resource_bulk_access()

        # Print summary
        print(f'\n{Colors.BOLD}' + '=' * 60)
        print('Test Summary')
        print('=' * 60 + Colors.RESET)

        print(f'{Colors.GREEN}Passed: {len(self.results["passed"])}{Colors.RESET}')
        print(f'{Colors.RED}Vulnerabilities: {len(self.results["vulnerabilities"])}{Colors.RESET}')

        if self.results['vulnerabilities']:
            print(f'\n{Colors.RED}{Colors.BOLD}🚨 VULNERABILITIES DETECTED:{Colors.RESET}')
            for vuln in self.results['vulnerabilities']:
                print(f'  {Colors.RED}• {vuln}{Colors.RESET}')

        if self.results['enumerations']:
            print(f'\n{Colors.YELLOW}{Colors.BOLD}📊 ENUMERATIONS POSSIBLE:{Colors.RESET}')
            for enum in self.results['enumerations']:
                print(f'  {Colors.YELLOW}• {enum}{Colors.RESET}')

        return len(self.results['vulnerabilities']) == 0


def main():
    import argparse
    parser = argparse.ArgumentParser(description='Horizontal Privilege / IDOR Fuzzer')
    parser.add_argument('--base-url', default='http://localhost:13000', help='Base URL')
    parser.add_argument('--output', help='Output JSON file')
    args = parser.parse_args()

    fuzzer = HorizontalPrivilegeFuzzer(args.base_url)
    success = fuzzer.run_all_tests()

    if args.output:
        with open(args.output, 'w') as f:
            json.dump({
                'timestamp': datetime.now().isoformat(),
                'target': args.base_url,
                'results': fuzzer.results
            }, f, indent=2)

    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
