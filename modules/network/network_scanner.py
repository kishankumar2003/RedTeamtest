import asyncio
import nmap
import json
import os
from datetime import datetime
from typing import Dict, List, Any, Optional
from loguru import logger
from rich.progress import Progress

class NetworkScanner:
    def __init__(self, target: str, output_dir: str):
        """
        Initialize NetworkScanner
        
        Args:
            target (str): Target IP or domain
            output_dir (str): Directory to save results
        """
        self.target = target
        self.output_dir = output_dir
        self.nm = nmap.PortScanner()
        self.results: Dict[str, Any] = {}
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

    async def run_all_scans(self) -> Dict[str, Any]:
        """
        Run all network scanning tasks
        
        Returns:
            Dict[str, Any]: Combined scan results
        """
        with Progress() as progress:
            task1 = progress.add_task("[cyan]Running port scan...", total=100)
            task2 = progress.add_task("[cyan]Running service detection...", total=100)
            task3 = progress.add_task("[cyan]Running OS detection...", total=100)
            task4 = progress.add_task("[cyan]Running script scan...", total=100)

            # Run port scan
            port_results = await self.port_scan()
            self.results['port_scan'] = port_results
            progress.update(task1, completed=100)

            # Run service detection
            service_results = await self.service_detection()
            self.results['service_detection'] = service_results
            progress.update(task2, completed=100)

            # Run OS detection
            os_results = await self.os_detection()
            self.results['os_detection'] = os_results
            progress.update(task3, completed=100)

            # Run script scan
            script_results = await self.script_scan()
            self.results['script_scan'] = script_results
            progress.update(task4, completed=100)

        # Save results
        self.save_results()
        return self.results

    async def port_scan(self) -> Dict[str, Any]:
        """
        Perform port scan
        
        Returns:
            Dict[str, Any]: Port scan results
        """
        try:
            logger.info(f"Starting port scan on {self.target}")
            self.nm.scan(self.target, arguments='-p- -T4')
            
            results = {}
            for host in self.nm.all_hosts():
                results[host] = {
                    'state': self.nm[host].state(),
                    'ports': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        results[host]['ports'][str(port)] = {
                            'state': self.nm[host][proto][port]['state'],
                            'service': self.nm[host][proto][port]['name']
                        }
            
            return results
        
        except Exception as e:
            logger.error(f"Error during port scan: {str(e)}")
            return {'error': str(e)}

    async def service_detection(self) -> Dict[str, Any]:
        """
        Perform service detection
        
        Returns:
            Dict[str, Any]: Service detection results
        """
        try:
            logger.info(f"Starting service detection on {self.target}")
            self.nm.scan(self.target, arguments='-sV')
            
            results = {}
            for host in self.nm.all_hosts():
                results[host] = {
                    'services': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        results[host]['services'][str(port)] = {
                            'name': self.nm[host][proto][port]['name'],
                            'product': self.nm[host][proto][port]['product'],
                            'version': self.nm[host][proto][port]['version'],
                            'extrainfo': self.nm[host][proto][port]['extrainfo']
                        }
            
            return results
        
        except Exception as e:
            logger.error(f"Error during service detection: {str(e)}")
            return {'error': str(e)}

    async def os_detection(self) -> Dict[str, Any]:
        """
        Perform OS detection
        
        Returns:
            Dict[str, Any]: OS detection results
        """
        try:
            logger.info(f"Starting OS detection on {self.target}")
            self.nm.scan(self.target, arguments='-O')
            
            results = {}
            for host in self.nm.all_hosts():
                if 'osmatch' in self.nm[host]:
                    results[host] = {
                        'os_matches': self.nm[host]['osmatch'],
                        'os_class': self.nm[host].get('osclass', [])
                    }
                else:
                    results[host] = {
                        'os_matches': [],
                        'os_class': []
                    }
            
            return results
        
        except Exception as e:
            logger.error(f"Error during OS detection: {str(e)}")
            return {'error': str(e)}

    async def script_scan(self) -> Dict[str, Any]:
        """
        Perform script scan
        
        Returns:
            Dict[str, Any]: Script scan results
        """
        try:
            logger.info(f"Starting script scan on {self.target}")
            self.nm.scan(self.target, arguments='--script=default')
            
            results = {}
            for host in self.nm.all_hosts():
                results[host] = {
                    'scripts': {}
                }
                
                for proto in self.nm[host].all_protocols():
                    ports = self.nm[host][proto].keys()
                    for port in ports:
                        if 'script' in self.nm[host][proto][port]:
                            results[host]['scripts'][str(port)] = self.nm[host][proto][port]['script']
            
            return results
        
        except Exception as e:
            logger.error(f"Error during script scan: {str(e)}")
            return {'error': str(e)}

    def save_results(self) -> None:
        """Save scan results to file"""
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = os.path.join(self.output_dir, f'network_scan_{timestamp}.json')
        
        try:
            with open(filename, 'w') as f:
                json.dump(self.results, f, indent=4)
            logger.info(f"Results saved to {filename}")
        except Exception as e:
            logger.error(f"Error saving results: {str(e)}")

    def get_open_ports(self) -> List[int]:
        """
        Get list of open ports
        
        Returns:
            List[int]: List of open ports
        """
        open_ports = []
        for host in self.results.get('port_scan', {}).keys():
            ports = self.results['port_scan'][host].get('ports', {})
            for port, info in ports.items():
                if info.get('state') == 'open':
                    open_ports.append(int(port))
        return sorted(open_ports)

    def get_detected_services(self) -> Dict[str, str]:
        """
        Get detected services
        
        Returns:
            Dict[str, str]: Dictionary of port to service mappings
        """
        services = {}
        for host in self.results.get('service_detection', {}).keys():
            service_info = self.results['service_detection'][host].get('services', {})
            for port, info in service_info.items():
                services[port] = info.get('name', 'unknown')
        return services

    def get_os_info(self) -> Optional[Dict[str, Any]]:
        """
        Get OS detection information
        
        Returns:
            Optional[Dict[str, Any]]: OS detection information if available
        """
        for host in self.results.get('os_detection', {}).keys():
            return self.results['os_detection'][host]
        return None
