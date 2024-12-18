#!/usr/bin/env python3

import argparse
import asyncio
import os
import sys
import yaml
from datetime import datetime
from rich.console import Console
from rich.progress import Progress
from loguru import logger
from typing import Dict, List

# Import modules
from modules.network.network_scanner import NetworkScanner
from modules.web.webapp_scanner import WebAppScanner
from modules.email.email_harvester import EmailHarvester
from modules.dns.dns_recon import DNSRecon
from modules.core.recursive_scanner import RecursiveScanner
from core.utils import setup_logging, load_config, validate_target, Logger, ConfigManager

console = Console()

class NexusGuard:
    def __init__(self):
        self.config = ConfigManager()
        Logger.setup()
        self.logger = logging.getLogger(__name__)
        self.console = Console()
        self.modules = {
            'network': NetworkScanner,
            'webapp': WebAppScanner,
            'email': EmailHarvester,
            'dns': DNSRecon
        }

    def load_configuration(self):
        """Load configuration from YAML file"""
        config_path = os.path.join('config', 'config.yml')
        if not os.path.exists(config_path):
            config_path = os.path.join('config', 'config.example.yml')
        
        try:
            with open(config_path, 'r') as f:
                return yaml.safe_load(f)
        except Exception as e:
            console.print(f"[red]Error loading configuration: {str(e)}[/red]")
            sys.exit(1)

    def setup_logging(self):
        """Setup logging configuration"""
        log_config = self.config['logging']
        logger.remove()  # Remove default handler
        
        # Add console handler
        logger.add(sys.stderr, level=log_config['levels']['console'])
        
        # Add file handler
        os.makedirs(os.path.dirname(log_config['file']), exist_ok=True)
        logger.add(
            log_config['file'],
            rotation=f"{log_config['max_size']} bytes",
            retention=log_config['backup_count'],
            level=log_config['levels']['file'],
            format=log_config['format']
        )

    async def run_module(self, module_name, target, output_dir):
        """Run a specific module"""
        if module_name not in self.modules:
            console.print(f"[red]Module {module_name} not found[/red]")
            return False

        try:
            module = self.modules[module_name](target, output_dir)
            await module.run_all_scans()
            return True
        except Exception as e:
            logger.error(f"Error in module {module_name}: {str(e)}")
            return False

    async def run_full_scan(self, target, output_dir):
        """Run all modules for a full security assessment"""
        results = {}
        
        with Progress() as progress:
            total = progress.add_task("[cyan]Running full security assessment...", total=len(self.modules))
            
            for module_name, module_class in self.modules.items():
                console.print(f"\n[cyan]Running {module_name} module...[/cyan]")
                try:
                    module = module_class(target, output_dir)
                    await module.run_all_scans()
                    results[module_name] = "Success"
                except Exception as e:
                    logger.error(f"Error in {module_name} module: {str(e)}")
                    results[module_name] = f"Failed: {str(e)}"
                
                progress.update(total, advance=1)
        
        return results

    async def run_scan(self, target: str, recursive: bool = False, max_depth: int = 2) -> Dict:
        """Run security scan on target."""
        try:
            if recursive:
                scanner = RecursiveScanner(max_depth=max_depth)
                results = await scanner.scan_target(target)
                stats = scanner.get_statistics()
                self._print_recursive_results(results, stats)
            else:
                # Regular non-recursive scan
                scanner = RecursiveScanner(max_depth=0)
                results = await scanner.scan_target(target)
                self._print_results(results)
            
            return results
        except Exception as e:
            self.logger.error(f"Scan failed: {str(e)}")
            return {"error": str(e)}

    def _print_recursive_results(self, results: Dict, stats: Dict):
        """Print recursive scan results in a structured format."""
        # Print statistics
        stats_table = Table(title="Scan Statistics")
        stats_table.add_column("Metric")
        stats_table.add_column("Value")
        
        for key, value in stats.items():
            if key != 'scanned_targets':
                stats_table.add_row(key, str(value))
        
        self.console.print(stats_table)

        # Print results for each target
        for target, data in results.items():
            self._print_target_results(target, data)

    def _print_target_results(self, target: str, data: Dict, indent: int = 0):
        """Print results for a single target."""
        prefix = "  " * indent
        self.console.print(f"\n{prefix}Target: {target}")
        
        if 'network' in data:
            self._print_network_results(data['network'], indent + 1)
        if 'web' in data:
            self._print_web_results(data['web'], indent + 1)
        if 'subdomains' in data:
            for subdomain, subdomain_data in data['subdomains'].items():
                self._print_target_results(subdomain, subdomain_data, indent + 1)

    def _print_network_results(self, network_data: Dict, indent: int):
        """Print network scan results."""
        prefix = "  " * indent
        if 'open_ports' in network_data:
            self.console.print(f"\n{prefix}Open Ports:")
            for port in network_data['open_ports']:
                self.console.print(f"{prefix}  {port['port']}/tcp - {port['service']} ({port.get('version', 'unknown')})")

    def _print_web_results(self, web_data: Dict, indent: int):
        """Print web scan results."""
        prefix = "  " * indent
        if 'vulnerabilities' in web_data:
            self.console.print(f"\n{prefix}Web Vulnerabilities:")
            for vuln in web_data['vulnerabilities']:
                self.console.print(f"{prefix}  {vuln['type']} - {vuln['severity']}")

    def _print_results(self, results: Dict):
        """Print non-recursive scan results."""
        for module, data in results.items():
            if module == 'network':
                self._print_network_results(data)
            elif module == 'web':
                self._print_web_results(data)

def main():
    parser = argparse.ArgumentParser(description="NexusGuard Security Framework")
    parser.add_argument("-m", "--module", choices=['network', 'webapp', 'email', 'dns'],
                      help="Specific module to run")
    parser.add_argument("-t", "--target", required=True,
                      help="Target domain or IP address")
    parser.add_argument("-o", "--output", default="reports/outputs",
                      help="Output directory for reports")
    parser.add_argument("--full", action="store_true",
                      help="Run full security assessment")
    parser.add_argument("-r", "--recursive", action="store_true", help="Enable recursive scanning")
    parser.add_argument("-d", "--depth", type=int, default=2, help="Maximum recursion depth")
    args = parser.parse_args()

    # Create output directory
    os.makedirs(args.output, exist_ok=True)

    # Initialize NexusGuard
    nexusguard = NexusGuard()

    # Validate target
    if not validate_target(args.target):
        console.print("[red]Invalid target specified[/red]")
        sys.exit(1)

    # Run assessment
    try:
        if args.full:
            results = asyncio.run(nexusguard.run_full_scan(args.target, args.output))
            nexusguard.generate_final_report(results, args.output)
        elif args.module:
            success = asyncio.run(nexusguard.run_module(args.module, args.target, args.output))
            if not success:
                sys.exit(1)
        elif args.recursive:
            results = asyncio.run(nexusguard.run_scan(args.target, args.recursive, args.depth))
        else:
            console.print("[red]Please specify a module or use --full for full assessment[/red]")
            sys.exit(1)

        console.print("[green]Assessment completed successfully![/green]")

    except KeyboardInterrupt:
        console.print("\n[yellow]Assessment interrupted by user[/yellow]")
        sys.exit(0)
    except Exception as e:
        console.print(f"[red]Error during assessment: {str(e)}[/red]")
        logger.exception("Error during assessment")
        sys.exit(1)

if __name__ == "__main__":
    main()
