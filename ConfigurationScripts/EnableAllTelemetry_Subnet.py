#!/usr/bin/env python3
"""
Dell iDRAC Telemetry - FAST Enable All Reports.

Optimized with parallel processing and connection pooling.
Supports iDRAC 9 and iDRAC 10.
"""

import sys
import time
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Optional, Any

import requests
import urllib3

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Logging configuration
logging.basicConfig(
    format='%(message)s',
    stream=sys.stdout,
    level=logging.INFO
)

#####################################################
# CONFIGURATION
#####################################################

USERNAME: str = "root"
PASSWORD: str = "calvin"

SUBNETS: List[str] = [
    "192.168.10",
    "192.158.10",
]

IP_LIST: List[str] = [
    # "100.96.45.205",
    # "100.96.45.206",
]

PARALLEL_JOBS: int = 250
REPORT_WORKERS: int = 10
TIMEOUT: int = 5

LOG_FILE: str = f"telemetry_{datetime.now().strftime('%Y%m%d_%H%M%S')}.log"


def get_report_definitions(
    ip_address: str,
    user: str,
    password: str,
    session: requests.Session
) -> Optional[List[str]]:
    """
    Fetch available report definitions from iDRAC.

    Args:
        ip_address: iDRAC IP address
        user: Username for authentication
        password: Password for authentication
        session: Requests session object

    Returns:
        List of report names or None if failed
    """
    url = f"https://{ip_address}/redfish/v1/TelemetryService/MetricReportDefinitions"
    try:
        response = session.get(
            url,
            auth=(user, password),
            verify=False,
            timeout=TIMEOUT
        )
        if response.status_code == 200:
            data = response.json()
            reports = [
                member['@odata.id'].split('/')[-1]
                for member in data.get('Members', [])
            ]
            return reports
    except (requests.exceptions.RequestException, ValueError, KeyError):
        pass
    return None


def enable_report(
    session: requests.Session,
    url: str,
    user: str,
    password: str
) -> bool:
    """
    Enable a single telemetry report.

    Args:
        session: Requests session object
        url: Report URL to enable
        user: Username for authentication
        password: Password for authentication

    Returns:
        True if successful, False otherwise
    """
    try:
        data = {
            "MetricReportDefinitionEnabled": True,
            "Status": {"State": "Enabled"}
        }
        response = session.patch(
            url,
            json=data,
            auth=(user, password),
            verify=False,
            timeout=TIMEOUT
        )
        return response.status_code in [200, 202, 204]
    except requests.exceptions.RequestException:
        return False


def configure_server(server_info: Dict[str, str]) -> Dict[str, Any]:
    """
    Configure telemetry for a single server.

    Args:
        server_info: Dictionary containing ip, username, password

    Returns:
        Dictionary with ip, status, and message
    """
    ip_address = server_info['ip']
    user = server_info['username']
    password = server_info['password']

    session = requests.Session()
    session.verify = False

    try:
        base_url = f"https://{ip_address}/redfish/v1/TelemetryService"

        # Step 1: Enable Telemetry Service
        response = session.patch(
            base_url,
            json={"ServiceEnabled": True},
            auth=(user, password),
            timeout=TIMEOUT
        )

        if response.status_code not in [200, 202, 204]:
            return {
                'ip': ip_address,
                'status': 'FAIL',
                'message': f"Service HTTP {response.status_code}"
            }

        # Step 2: Get available reports dynamically
        reports = get_report_definitions(ip_address, user, password, session)
        if not reports:
            return {
                'ip': ip_address,
                'status': 'FAIL',
                'message': "Cannot get reports"
            }

        # Step 3: Enable all reports in parallel
        success = 0
        report_urls = [
            f"{base_url}/MetricReportDefinitions/{report}"
            for report in reports
        ]

        with ThreadPoolExecutor(max_workers=REPORT_WORKERS) as executor:
            futures = [
                executor.submit(enable_report, session, url, user, password)
                for url in report_urls
            ]
            for future in as_completed(futures):
                if future.result():
                    success += 1

        return {
            'ip': ip_address,
            'status': 'OK',
            'message': f"{success}/{len(reports)}"
        }

    except requests.exceptions.ConnectTimeout:
        return {
            'ip': ip_address,
            'status': 'FAIL',
            'message': "Timeout"
        }
    except requests.exceptions.ConnectionError:
        return {
            'ip': ip_address,
            'status': 'FAIL',
            'message': "No connection"
        }
    except requests.exceptions.RequestException as err:
        return {
            'ip': ip_address,
            'status': 'FAIL',
            'message': str(err)[:30]
        }
    finally:
        session.close()


def generate_servers() -> List[Dict[str, str]]:
    """
    Generate server list from subnets or IP list.

    Returns:
        List of server dictionaries with ip, username, password
    """
    servers: List[Dict[str, str]] = []

    if IP_LIST:
        for ip_address in IP_LIST:
            servers.append({
                'ip': ip_address,
                'username': USERNAME,
                'password': PASSWORD
            })
    else:
        for subnet in SUBNETS:
            for i in range(1, 255):
                servers.append({
                    'ip': f"{subnet}.{i}",
                    'username': USERNAME,
                    'password': PASSWORD
                })

    return servers


def run_parallel(servers: List[Dict[str, str]]) -> tuple:
    """
    Run telemetry configuration in parallel.

    Args:
        servers: List of server dictionaries

    Returns:
        Tuple of (success_count, fail_count, duration)
    """
    success_count = 0
    fail_count = 0
    start_time = time.time()

    with open(LOG_FILE, 'w', encoding='utf-8') as log:
        with ThreadPoolExecutor(max_workers=PARALLEL_JOBS) as executor:
            futures = {
                executor.submit(configure_server, server): server
                for server in servers
            }

            for future in as_completed(futures):
                result = future.result()

                if result['status'] == 'OK':
                    output = f"[OK] {result['ip']}: {result['message']}"
                    success_count += 1
                else:
                    output = f"[FAIL] {result['ip']}: {result['message']}"
                    fail_count += 1

                print(output)
                log.write(output + "\n")

    duration = int(time.time() - start_time)
    return success_count, fail_count, duration


def main() -> None:
    """Main function to run telemetry configuration."""
    print()
    print("==============================================")
    print("Dell iDRAC Telemetry - FAST Enable")
    print("==============================================")
    print(f"Username:        {USERNAME}")

    if IP_LIST:
        print("Subnets:         Using IP_LIST")
    else:
        print(f"Subnets:         {', '.join(SUBNETS)}")

    print(f"Parallel Jobs:   {PARALLEL_JOBS}")
    print(f"Report Workers:  {REPORT_WORKERS}")
    print(f"Timeout:         {TIMEOUT} sec")
    print("==============================================")
    print()

    servers = generate_servers()
    print(f"Total Servers: {len(servers)}")
    print()

    print("Enabling Telemetry...")
    print("==============================================")

    success_count, fail_count, duration = run_parallel(servers)

    print()
    print("==============================================")
    print("SUMMARY")
    print("==============================================")
    print(f"Total Servers:  {len(servers)}")
    print(f"Successful:     {success_count}")
    print(f"Failed:         {fail_count}")
    print(f"Duration:       {duration} seconds")
    print(f"Log File:       {LOG_FILE}")
    print("==============================================")


if __name__ == "__main__":
    main()

