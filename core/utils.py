import os
import re
import yaml
import socket
from urllib.parse import urlparse
from datetime import datetime
from typing import Dict, Any, Union
from loguru import logger

def load_config(config_path: str = None) -> Dict[str, Any]:
    """
    Load configuration from YAML file
    
    Args:
        config_path (str): Path to configuration file
        
    Returns:
        Dict[str, Any]: Configuration dictionary
    """
    if not config_path:
        config_path = os.path.join('config', 'config.yml')
        if not os.path.exists(config_path):
            config_path = os.path.join('config', 'config.example.yml')
    
    try:
        with open(config_path, 'r') as f:
            return yaml.safe_load(f)
    except Exception as e:
        logger.error(f"Error loading configuration: {str(e)}")
        return {}

def setup_logging(config: Dict[str, Any]) -> None:
    """
    Setup logging configuration
    
    Args:
        config (Dict[str, Any]): Configuration dictionary
    """
    log_config = config.get('logging', {})
    
    # Remove default handler
    logger.remove()
    
    # Add console handler
    console_level = log_config.get('levels', {}).get('console', 'INFO')
    logger.add(sys.stderr, level=console_level)
    
    # Add file handler
    log_file = log_config.get('file', 'logs/nexusguard.log')
    os.makedirs(os.path.dirname(log_file), exist_ok=True)
    
    logger.add(
        log_file,
        rotation=log_config.get('max_size', '10 MB'),
        retention=log_config.get('backup_count', 5),
        level=log_config.get('levels', {}).get('file', 'DEBUG'),
        format=log_config.get('format', '{time} - {name} - {level} - {message}')
    )

def validate_target(target: str) -> bool:
    """
    Validate target domain or IP address
    
    Args:
        target (str): Target domain or IP address
        
    Returns:
        bool: True if valid, False otherwise
    """
    # Check if it's an IP address
    try:
        socket.inet_aton(target)
        return True
    except socket.error:
        pass
    
    # Check if it's a domain
    domain_pattern = r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$'
    if re.match(domain_pattern, target):
        return True
    
    # Check if it's a URL
    try:
        result = urlparse(target)
        return all([result.scheme, result.netloc])
    except Exception:
        return False

def create_output_directory(base_dir: str, target: str) -> str:
    """
    Create output directory for scan results
    
    Args:
        base_dir (str): Base output directory
        target (str): Target being scanned
        
    Returns:
        str: Path to created directory
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    target_dir = re.sub(r'[^\w\-_]', '_', target)
    output_dir = os.path.join(base_dir, f"{target_dir}_{timestamp}")
    os.makedirs(output_dir, exist_ok=True)
    return output_dir

def is_port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    """
    Check if a port is open
    
    Args:
        host (str): Target host
        port (int): Port to check
        timeout (float): Timeout in seconds
        
    Returns:
        bool: True if port is open, False otherwise
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((host, port))
            return True
    except (socket.timeout, socket.error):
        return False

def get_ip_address(domain: str) -> Union[str, None]:
    """
    Get IP address for a domain
    
    Args:
        domain (str): Domain name
        
    Returns:
        Union[str, None]: IP address if resolved, None otherwise
    """
    try:
        return socket.gethostbyname(domain)
    except socket.gaierror:
        return None

def sanitize_filename(filename: str) -> str:
    """
    Sanitize filename by removing invalid characters
    
    Args:
        filename (str): Original filename
        
    Returns:
        str: Sanitized filename
    """
    # Remove invalid characters
    filename = re.sub(r'[<>:"/\\|?*]', '', filename)
    # Replace spaces with underscores
    filename = filename.replace(' ', '_')
    return filename

def parse_url(url: str) -> Dict[str, str]:
    """
    Parse URL into components
    
    Args:
        url (str): URL to parse
        
    Returns:
        Dict[str, str]: Dictionary of URL components
    """
    parsed = urlparse(url)
    return {
        'scheme': parsed.scheme,
        'netloc': parsed.netloc,
        'path': parsed.path,
        'params': parsed.params,
        'query': parsed.query,
        'fragment': parsed.fragment
    }

def format_duration(seconds: float) -> str:
    """
    Format duration in seconds to human readable string
    
    Args:
        seconds (float): Duration in seconds
        
    Returns:
        str: Formatted duration string
    """
    hours = int(seconds // 3600)
    minutes = int((seconds % 3600) // 60)
    seconds = int(seconds % 60)
    
    parts = []
    if hours > 0:
        parts.append(f"{hours}h")
    if minutes > 0:
        parts.append(f"{minutes}m")
    if seconds > 0 or not parts:
        parts.append(f"{seconds}s")
    
    return " ".join(parts)

def get_timestamp() -> str:
    """
    Get current timestamp in ISO format
    
    Returns:
        str: Current timestamp
    """
    return datetime.now().isoformat()

def validate_ip_address(ip: str) -> bool:
    """
    Validate IP address
    
    Args:
        ip (str): IP address to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    try:
        socket.inet_pton(socket.AF_INET, ip)
        return True
    except socket.error:
        try:
            socket.inet_pton(socket.AF_INET6, ip)
            return True
        except socket.error:
            return False

def is_valid_port(port: int) -> bool:
    """
    Check if port number is valid
    
    Args:
        port (int): Port number to validate
        
    Returns:
        bool: True if valid, False otherwise
    """
    return isinstance(port, int) and 0 <= port <= 65535
