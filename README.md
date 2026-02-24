# EVA Upgraded - Google Maps API Scanner by Bar Hajby

**Enhanced version with 32+ API endpoint checks**

Used for determining whether a leaked/found Google Maps API Key is vulnerable to unauthorized access by other applications or not.

***Original tool by [Ozgur Alp](https://github.com/ozguralp/gmapsapiscanner)***

***[Blog Post #1 - Unauthorized Google Maps API Key Usage Cases](https://medium.com/bugbountywriteup/unauthorized-google-maps-api-key-usage-cases-and-why-you-need-to-care-1ccb28bf21e)***

***[Blog Post #2 - Google Maps API Bugs Over the Years](https://medium.com/bugbountywriteup/google-maps-api-not-the-key-bugs-that-i-found-over-the-years-781840fc82aa)***


---

## Usage

### Single Key Mode

```bash
# Direct usage
python eva_gmaps_scanner.py --api-key YOUR_KEY

# With proxy (defaults to 127.0.0.1:8080)
python eva_gmaps_scanner.py --api-key YOUR_KEY -p

# With custom proxy
python eva_gmaps_scanner.py --api-key YOUR_KEY --proxy http://proxy.example.com:3128
```

### Batch Mode (Multiple Keys)

Test multiple API keys and get a comparison table:

```bash
# Test multiple keys from file
python eva_gmaps_scanner.py --list keys.txt

# With proxy
python eva_gmaps_scanner.py -l keys.txt -p
```

**File format** (`keys.txt`):
```
AIzaSyDXXXXXXXXX
AIzaSyEYYYYYYYYY
AIzaSyFZZZZZZZZZ
```
Or comma-separated: `AIzaSyD..., AIzaSyE..., AIzaSyF...`

**Batch mode output:**
- Tests each endpoint against ALL keys before moving to next
- Generates a comparison table showing which APIs are vulnerable for each key
- Perfect for testing multiple keys from the same project

**Example output table:**
```
====================================================================================================
📊 BATCH SCAN RESULTS - Vulnerable Endpoints per API Key
====================================================================================================
API Endpoint                             | AIzaSyDXXXXXXXXX...   | AIzaSyEYYYYYYYYY...   | AIzaSyFZZZZZZZZZ...  
----------------------------------------------------------------------------------------------------
Staticmap API                            | ✓ VULN                | ✗ Safe                | ✓ VULN               
Streetview API                           | ✓ VULN                | ✗ Safe                | ✗ Safe               
Directions API                           | ✓ VULN                | ✓ VULN                | ✓ VULN               
Geocode API                              | ✗ Safe                | ✓ VULN                | ✓ VULN               
...
====================================================================================================

📈 SUMMARY:
  Key 1 (AIzaSyDXXXXXXXXX...): 15/32 APIs vulnerable
  Key 2 (AIzaSyEYYYYYYYYY...): 8/32 APIs vulnerable
  Key 3 (AIzaSyFZZZZZZZZZ...): 12/32 APIs vulnerable
```

**Options:**
- `-a, --api-key KEY` - Single Google Maps API key to test
- `-l, --list FILE` - File containing multiple API keys (batch mode)
- `-p, --proxy [URL]` - Route through proxy (default: `http://127.0.0.1:8080`)
- `-h, --help` - Show help message

Script returns `API key is vulnerable for XXX API!` with PoC links/commands for any unauthorized access detected.

---

## Checked APIs (32 Total)

### Legacy APIs (v1)
1. Staticmap API - $2/1K requests
2. Streetview API - $7/1K requests
3. Directions API - $5/1K requests
4. Geocode API - $5/1K requests
5. Distance Matrix API - $5/1K elements
6. Find Place From Text API - $17/1K requests
7. Autocomplete API - $2.83/1K requests
8. Query Autocomplete API - $2.83/1K requests
9. Elevation API - $5/1K requests
10. Timezone API - $5/1K requests
11. Nearest Roads API - $10/1K requests
12. Snap to Roads API - $10/1K requests
13. Speed Limits API - $20/1K requests
14. Place Details API - $17/1K requests
15. Nearby Search API - $32/1K requests
16. Text Search API - $32/1K requests
17. Places Photo API - $7/1K requests
18. Geolocation API - $5/1K requests

### Next-Gen APIs (v2)
19. Routes API (Compute Routes) - $5/1K requests
20. Routes API (Route Matrix) - $10/1K elements
21. Places API (Nearby Search - New) - $32/1K requests
22. Places API (Text Search - New) - $32/1K requests
23. Address Validation API - $17/1K requests

### Environmental & Specialized APIs
24. Air Quality API - Contact Google
25. Pollen API - Contact Google
26. Solar API - Contact Google
27. Aerial View API - Contact Google
28. Playable Locations API - Contact Google

### Web APIs
29. Map Tiles API - $2/1K requests
30. Maps Embed API - Free (with restrictions)
31. Maps JavaScript API - $7/1K requests (automated + manual check)
32. FCM API - Takeover vulnerability

---

## Features

✅ **32 API endpoint checks** (vs 19 in original)  
✅ **Batch testing** - Test multiple keys with comparison table  
✅ **Organized output** - Numbered tests with separators  
✅ **Latest API versions** - Routes v2, Places v2  
✅ **New environmental APIs** - Air Quality, Pollen, Solar  
✅ **Automated + Manual** JavaScript API testing  
✅ **Cost information** for each vulnerable API  
✅ **Proxy support** - Route requests through proxy (Burp Suite, etc.)  
✅ **Flexible input** - Single key or batch file (newline/comma separated)  

---

## Notes

- JavaScript API offers both automated check and optional manual browser verification
- For Staticmap, Streetview, and Embed APIs: If script shows vulnerable but browser reproduction fails, check **Blog Post #2** for server-side vulnerability details
- Referer checks may affect results when testing from different domains
- Special thanks to [Yatin](https://twitter.com/ysirpaul) for contributions on API discovery & cost information!

---

## Docker

Run in a Dockerized Alpine Linux environment:

```bash
docker build -t eva_gmaps_scanner .
docker run --rm -v $(pwd):/opt/html -i eva_gmaps_scanner <api-key>
```

---

## Credits

- **Original Tool**: [Ozgur Alp](https://github.com/ozguralp/gmapsapiscanner)
- **EVA Upgrade**: Bar Hajby (2025)
- **Contributors**: [Yatin](https://twitter.com/ysirpaul)

---

**Version**: EVA 1.1 (Enhanced with 32 API checks + Batch Testing)
