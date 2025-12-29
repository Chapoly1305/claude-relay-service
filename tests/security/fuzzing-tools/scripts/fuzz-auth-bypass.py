#!/usr/bin/env python3
"""
Authentication Bypass Fuzzer for Claude Relay Service

Tests the authenticateUserOrAdmin middleware for the CVE-1 vulnerability:
- Missing required fields validation
- Session injection attacks
- Privilege escalation

Validates that the security fix (commit 45b81bd) stays in place.

Usage:
    python3 fuzz-auth-bypass.py --base-url http://localhost:13000
    python3 fuzz-auth-bypass.py --base-url http://localhost:13000 --output results.json
"""

import sys
import json
import argparse
import requests
from datetime import datetime
from typing import Dict, List, Tuple
from urllib.parse import urljoin

# Colors for terminal output
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'
    BOLD = '\033[1m'


class AuthBypassFuzzer:
    """Fuzzes authentication bypass vulnerabilities in Claude Relay Service."""

    def __init__(self, base_url: str = 'http://localhost:13000', verbose: bool = False):
        self.base_url = base_url.rstrip('/')
        self.verbose = verbose
        self.session = requests.Session()
        self.timeout = 10

        # Test cases for authenticateUserOrAdmin
        self.test_cases = {
            'valid_admin_token_with_proper_length_for_testing': {
                'description': 'Valid complete session (baseline)',
                'expected_status': 200,
                'critical': False,
                'severity': 'baseline'
            },
            'empty_session_token_with_proper_length_for_testing': {
                'description': 'Empty object {} (should fail)',
                'expected_status': 401,
                'critical': True,
                'severity': 'critical'
            },
            'missing_username_token_with_proper_testing_length': {
                'description': 'Missing username field (CVE-1)',
                'expected_status': 401,
                'critical': True,
                'severity': 'critical'
            },
            'missing_logintime_token_with_proper_testing_length': {
                'description': 'Missing loginTime field (CVE-1)',
                'expected_status': 401,
                'critical': True,
                'severity': 'critical'
            },
            'random_field_token_with_proper_testing_length': {
                'description': 'Random field only {foo: bar} (CVE-1 critical)',
                'expected_status': 401,
                'critical': True,
                'severity': 'critical'
            },
            'expired_session_token_with_proper_testing_length': {
                'description': 'Expired session (25h+ old) - no expiry check',
                'expected_status': 200,
                'critical': False,
                'severity': 'info'
            },
            'partial_adminid_token_with_proper_testing_length': {
                'description': 'Missing adminId field - not required',
                'expected_status': 200,
                'critical': False,
                'severity': 'info'
            },
            'null_values_token_with_proper_testing_length': {
                'description': 'Null values - only username/loginTime checked',
                'expected_status': 200,
                'critical': False,
                'severity': 'info'
            }
        }

        # Endpoints that use authenticateUserOrAdmin
        self.endpoints = [
            '/users/',
            '/users/stats/overview',
            '/admin/webhook/config',
            '/admin/api-keys'
        ]

        # Results tracking
        self.results = {
            'passed': [],
            'failed': [],
            'errors': [],
            'endpoints_tested': {}
        }

    def test_endpoint(self, endpoint: str, token: str, expected_status: int) -> Tuple[bool, int, str]:
        """
        Test a single endpoint with a given token.

        Returns:
            Tuple[bool, int, str] - (success, status_code, error_message)
        """
        try:
            headers = {
                'Authorization': f'Bearer {token}',
                'Content-Type': 'application/json'
            }
            url = urljoin(self.base_url, endpoint)

            resp = self.session.get(url, headers=headers, timeout=self.timeout)

            success = resp.status_code == expected_status
            return (success, resp.status_code, '')

        except requests.exceptions.Timeout:
            return (False, 0, 'Request timeout')
        except requests.exceptions.ConnectionError:
            return (False, 0, f'Connection failed to {self.base_url}')
        except Exception as e:
            return (False, 0, str(e))

    def run_tests(self) -> bool:
        """Run all authentication bypass tests."""
        print(f'{Colors.BOLD}🧪 Authentication Bypass Fuzzing{Colors.RESET}')
        print('=' * 60)
        print(f'Target: {self.base_url}')
        print(f'Endpoints: {len(self.endpoints)}')
        print(f'Test cases: {len(self.test_cases)}')
        print('')

        # Verify connectivity
        print(f'{Colors.BLUE}[*] Checking connectivity...{Colors.RESET}')
        try:
            resp = self.session.get(
                urljoin(self.base_url, '/health'),
                timeout=self.timeout
            )
            if resp.status_code == 200:
                print(f'{Colors.GREEN}✓ Server is healthy{Colors.RESET}')
            else:
                print(f'{Colors.YELLOW}⚠ Health check returned {resp.status_code}{Colors.RESET}')
        except Exception as e:
            print(f'{Colors.RED}✗ Cannot reach server: {e}{Colors.RESET}')
            return False

        print('')

        # Run tests for each token against each endpoint
        for token, test_info in self.test_cases.items():
            print(f'{Colors.BOLD}Testing: {token}{Colors.RESET}')
            print(f'  Description: {test_info["description"]}')
            print(f'  Expected status: {test_info["expected_status"]}')
            print('')

            endpoint_results = []

            for endpoint in self.endpoints:
                success, status, error = self.test_endpoint(
                    endpoint,
                    token,
                    test_info['expected_status']
                )

                endpoint_results.append((endpoint, success, status))

                status_marker = f'{Colors.GREEN}✓{Colors.RESET}' if success else f'{Colors.RED}✗{Colors.RESET}'
                status_text = f'→ {endpoint}: {status_marker} (got {status})'

                if success:
                    self.results['passed'].append(f'{token} on {endpoint}')
                    print(f'  {Colors.GREEN}{status_text}{Colors.RESET}')
                else:
                    vulnerability_msg = f'VULNERABILITY: {test_info["description"]} returned {status}'
                    self.results['failed'].append(vulnerability_msg)
                    print(f'  {Colors.RED}{status_text}{Colors.RESET}')

                if error:
                    self.results['errors'].append(f'{endpoint}: {error}')
                    print(f'  {Colors.YELLOW}Error: {error}{Colors.RESET}')

            self.results['endpoints_tested'][token] = endpoint_results
            print('')

        # Print summary
        return self.print_summary()

    def print_summary(self) -> bool:
        """Print test summary and return True if all passed."""
        print('=' * 60)
        print(f'{Colors.BOLD}Test Summary{Colors.RESET}')
        print('=' * 60)

        passed = len(self.results['passed'])
        failed = len(self.results['failed'])
        errors = len(self.results['errors'])
        total = passed + failed

        print(f'Passed: {Colors.GREEN}{passed}{Colors.RESET}/{total}')
        print(f'Failed: {Colors.RED}{failed}{Colors.RESET}/{total}')

        if errors > 0:
            print(f'Errors: {Colors.YELLOW}{errors}{Colors.RESET}')

        print('')

        if failed > 0:
            print(f'{Colors.RED}{Colors.BOLD}VULNERABILITIES DETECTED!{Colors.RESET}')
            print('')
            for i, failure in enumerate(self.results['failed'], 1):
                print(f'{Colors.RED}  [{i}] {failure}{Colors.RESET}')
            print('')
            return False
        else:
            print(f'{Colors.GREEN}{Colors.BOLD}✓ All tests passed!{Colors.RESET}')
            print('   The authenticateUserOrAdmin vulnerability is fixed.')
            print('')
            return True

    def save_report(self, output_file: str) -> None:
        """Save results as JSON report."""
        report = {
            'timestamp': datetime.now().isoformat(),
            'target': self.base_url,
            'endpoints_tested': len(self.endpoints),
            'test_cases': len(self.test_cases),
            'summary': {
                'passed': len(self.results['passed']),
                'failed': len(self.results['failed']),
                'errors': len(self.results['errors'])
            },
            'vulnerable': len(self.results['failed']) > 0,
            'details': {
                'passed': self.results['passed'],
                'failed': self.results['failed'],
                'errors': self.results['errors']
            }
        }

        try:
            with open(output_file, 'w') as f:
                json.dump(report, f, indent=2)
            print(f'{Colors.GREEN}✓ Report saved: {output_file}{Colors.RESET}')
        except Exception as e:
            print(f'{Colors.RED}✗ Failed to save report: {e}{Colors.RESET}')


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description='Authentication Bypass Fuzzer for Claude Relay Service',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  %(prog)s
  %(prog)s --base-url http://localhost:13000
  %(prog)s --base-url http://test_relay:3000 --output results.json
  %(prog)s -v --base-url http://localhost:13000
        '''
    )

    parser.add_argument(
        '--base-url',
        default='http://localhost:13000',
        help='Base URL of the relay service (default: http://localhost:13000)'
    )

    parser.add_argument(
        '--output',
        help='Output file for JSON report'
    )

    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Verbose output'
    )

    args = parser.parse_args()

    # Run fuzzer
    fuzzer = AuthBypassFuzzer(base_url=args.base_url, verbose=args.verbose)
    success = fuzzer.run_tests()

    # Save report if requested
    if args.output:
        fuzzer.save_report(args.output)

    # Exit with appropriate code
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
