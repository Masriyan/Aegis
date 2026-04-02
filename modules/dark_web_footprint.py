import aiohttp
import asyncio
from typing import Dict, Any, Optional
from bs4 import BeautifulSoup
import re

from .base import BaseModule

class DarkWebFootprintModule(BaseModule):
    name = "dark_web_footprint"
    description = "Searches Dark Web repositories (Ahmia) for mentions of the target company/domain."
    category = "Threat Intelligence"
    dependencies = []
    
    # Needs a gentle rate limit out of respect for public Tor gateways
    rate_limit_rpm = 10 
    
    async def run(self, target: str, session: aiohttp.ClientSession, shared_state: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        domain = target.replace("https://", "").replace("http://", "").split("/")[0]
        keyword = domain.split(".")[0] # Just the base name for broader hits
        
        results = {
            "search_term": keyword,
            "mentions_found": 0,
            "onion_links": [],
            "risk_assessment": "Low"
        }
        
        await self._scrape_ahmia(session, keyword, results)
        
        if results["mentions_found"] > 0:
            results["risk_assessment"] = "High (Brand / Domain mentioned on Dark Web indexes)"
            
        return results

    async def _scrape_ahmia(self, session: aiohttp.ClientSession, keyword: str, results: Dict[str, Any]):
        """Scrape Ahmia.fi for mentions of the keyword."""
        # Ahmia allows basic searches through their clearnet presence
        url = f"https://ahmia.fi/search/?q=\"{keyword}\""
        
        headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Accept": "text/html"
        }
        try:
            async with session.get(url, headers=headers, timeout=15) as response:
                if response.status == 200:
                    html = await response.text()
                    soup = BeautifulSoup(html, "html.parser")
                    
                    search_results = soup.find_all("li", class_="searchResultsItem")
                    
                    results["mentions_found"] = len(search_results)
                    
                    for item in search_results[:5]: # Top 5
                        title_el = item.find("h4")
                        link_el = item.find("cite")
                        snippet_el = item.find("p")
                        
                        results["onion_links"].append({
                            "title": title_el.text.strip() if title_el else "Unknown",
                            "url": link_el.text.strip() if link_el else "Unknown",
                            "snippet": snippet_el.text.strip() if snippet_el else ""
                        })
        except Exception as e:
            # Handle rate limits or connection blocking smoothly
            pass
