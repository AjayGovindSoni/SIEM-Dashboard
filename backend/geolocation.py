"""
IP Geolocation service for geographic mapping
Uses GeoLite2 database or API for IP location lookup
"""

import requests
import logging
from typing import Dict, Any, Optional
from datetime import datetime, timedelta
from functools import lru_cache

logger = logging.getLogger(__name__)


class IPGeolocation:
    """IP Geolocation service"""
    
    def __init__(self, use_api: bool = True):
        self.use_api = use_api
        self.cache = {}
        self.cache_ttl = timedelta(hours=24)
    
    @lru_cache(maxsize=1000)
    def get_location(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get geographic location for an IP address"""
        if not ip_address or self._is_private_ip(ip_address):
            return None
        
        # Check cache
        if ip_address in self.cache:
            cached_data, cached_time = self.cache[ip_address]
            if datetime.now() - cached_time < self.cache_ttl:
                return cached_data
        
        try:
            if self.use_api:
                location_data = self._get_location_from_api(ip_address)
            else:
                location_data = self._get_location_from_database(ip_address)
            
            # Cache the result
            if location_data:
                self.cache[ip_address] = (location_data, datetime.now())
            
            return location_data
            
        except Exception as e:
            logger.error(f"Failed to get location for {ip_address}: {e}")
            return None
    
    def _get_location_from_api(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get location using free IP geolocation API"""
        try:
            # Using ip-api.com (free, no key required)
            response = requests.get(
                f"http://ip-api.com/json/{ip_address}",
                timeout=5
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('status') == 'success':
                    return {
                        'ip': ip_address,
                        'country': data.get('country'),
                        'country_code': data.get('countryCode'),
                        'region': data.get('regionName'),
                        'city': data.get('city'),
                        'latitude': data.get('lat'),
                        'longitude': data.get('lon'),
                        'timezone': data.get('timezone'),
                        'isp': data.get('isp'),
                        'org': data.get('org'),
                        'as': data.get('as')
                    }
            
            return None
            
        except Exception as e:
            logger.error(f"API geolocation failed for {ip_address}: {e}")
            return None
    
    def _get_location_from_database(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get location using local GeoLite2 database"""
        try:
            import geoip2.database
            
            # You would need to download GeoLite2-City.mmdb
            # from https://dev.maxmind.com/geoip/geoip2/geolite2/
            reader = geoip2.database.Reader('./GeoLite2-City.mmdb')
            response = reader.city(ip_address)
            
            return {
                'ip': ip_address,
                'country': response.country.name,
                'country_code': response.country.iso_code,
                'region': response.subdivisions.most_specific.name if response.subdivisions else None,
                'city': response.city.name,
                'latitude': response.location.latitude,
                'longitude': response.location.longitude,
                'timezone': response.location.time_zone,
                'accuracy_radius': response.location.accuracy_radius
            }
            
        except ImportError:
            logger.warning("geoip2 library not installed. Install with: pip install geoip2")
            return None
        except Exception as e:
            logger.error(f"Database geolocation failed for {ip_address}: {e}")
            return None
    
    def _is_private_ip(self, ip_address: str) -> bool:
        """Check if IP is private/internal"""
        try:
            import ipaddress
            ip = ipaddress.ip_address(ip_address)
            return ip.is_private or ip.is_loopback or ip.is_link_local
        except:
            return False
    
    def get_batch_locations(self, ip_addresses: list) -> Dict[str, Dict[str, Any]]:
        """Get locations for multiple IPs"""
        results = {}
        for ip in ip_addresses:
            location = self.get_location(ip)
            if location:
                results[ip] = location
        return results
    
    def get_threat_intelligence(self, ip_address: str) -> Optional[Dict[str, Any]]:
        """Get threat intelligence data for an IP (using AbuseIPDB or similar)"""
        try:
            # This is a placeholder - you would need an API key from AbuseIPDB
            # https://www.abuseipdb.com/
            
            # Example implementation:
            # api_key = "YOUR_ABUSEIPDB_API_KEY"
            # headers = {
            #     'Key': api_key,
            #     'Accept': 'application/json'
            # }
            # params = {
            #     'ipAddress': ip_address,
            #     'maxAgeInDays': '90'
            # }
            # response = requests.get(
            #     'https://api.abuseipdb.com/api/v2/check',
            #     headers=headers,
            #     params=params,
            #     timeout=5
            # )
            # if response.status_code == 200:
            #     data = response.json()['data']
            #     return {
            #         'ip': ip_address,
            #         'is_public': data.get('isPublic'),
            #         'abuse_confidence_score': data.get('abuseConfidenceScore'),
            #         'country_code': data.get('countryCode'),
            #         'is_whitelisted': data.get('isWhitelisted'),
            #         'total_reports': data.get('totalReports'),
            #         'last_reported': data.get('lastReportedAt')
            #     }
            
            return None
            
        except Exception as e:
            logger.error(f"Threat intelligence lookup failed for {ip_address}: {e}")
            return None


# Global geolocation service
geo_service = IPGeolocation(use_api=True)
