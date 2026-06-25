import requests
import warnings 
import json
import sys
import os
import argparse
from typing import List, Dict
from collections import defaultdict


def parse_api_keys_from_file(filepath: str) -> List[str]:
	"""Parse API keys from file. Supports newline and comma separation."""
	try:
		with open(filepath, 'r') as f:
			content = f.read()
		
		# Replace commas with newlines, then split by newlines
		keys = content.replace(',', '\n').split('\n')
		
		# Clean up: strip whitespace and filter empty strings
		keys = [key.strip() for key in keys if key.strip()]
		
		return keys
	except FileNotFoundError:
		print(f"Error: File '{filepath}' not found.")
		sys.exit(1)
	except Exception as e:
		print(f"Error reading file: {e}")
		sys.exit(1)


def print_results_table(results, api_keys):
    """Formatted comparison table of results for batch mode."""
    apis = sorted(results.keys())
    width = 100
    print("\n" + "=" * width)
    print("📊 BATCH SCAN RESULTS — EVA Google API Scanner")
    print("=" * width)
    print("🔑 API Keys tested:")
    for i, key in enumerate(api_keys, 1):
        cnt = sum(1 for api in apis if results[api].get(key, False))
        flag = "\033[1;31m" if cnt else "\033[0;32m"
        print(f"   Key {i}: {key}  {flag}[{cnt}/{len(apis)} vulnerable]\033[0m")
    print("-" * width)
    header = f"{'API Endpoint':<40}"
    for i, key in enumerate(api_keys, 1):
        header += f" | {'Key ' + str(i):<14}"
    print(header)
    print("-" * len(header))
    for api in apis:
        row = f"{api:<40}"
        for key in api_keys:
            vuln = results[api].get(key, False)
            status = "✓ VULN" if vuln else "✗ Safe"
            color = "\033[1;31m" if vuln else "\033[0;32m"
            row += f" | {color}{status:<14}\033[0m"
        print(row)
    print("=" * width)
    print("\n📈 SUMMARY:")
    for i, key in enumerate(api_keys, 1):
        cnt = sum(1 for api in apis if results[api].get(key, False))
        sev = "\033[1;31m" if cnt else "\033[0;32m"
        print(f"  {sev}Key {i}\033[0m  {key}  →  {sev}{cnt}/{len(apis)} APIs vulnerable\033[0m")
    print()


def print_single_table(apikey, vulnerable_apis, total_tested):
    """Final results table for single-key mode (consistent with the batch output)."""
    rows = []
    for entry in vulnerable_apis:
        if "||" in entry:
            name, cost = entry.split("||", 1)
        else:
            name, cost = entry, ""
        rows.append((name.replace("\t", " ").strip().rstrip("|").strip(), cost.strip()))
    width = 100
    print("\n" + "=" * width)
    print("📊 SCAN RESULTS — EVA Google API Scanner")
    print("=" * width)
    flag = "\033[1;31m" if rows else "\033[0;32m"
    verdict = "VULNERABLE" if rows else "SAFE / RESTRICTED"
    print(f"🔑 API Key tested : {apikey}")
    print(f"📈 Verdict        : {flag}{verdict}\033[0m  ({len(rows)} finding(s) across {total_tested} endpoints tested)")
    print("-" * width)
    print(f"  {'#':<3} {'VULNERABLE ENDPOINT':<45} | COST / EXPLOIT REFERENCE")
    print("-" * width)
    if rows:
        for i, (name, cost) in enumerate(rows, 1):
            print(f"  \033[1;31m{i:<3} {name:<45}\033[0m | {cost}")
    else:
        print("  \033[0;32m(none — key appears restricted / not vulnerable)\033[0m")
    print("=" * width)


def scan_gmaps(apikey, proxy_url=None):
	vulnerable_apis = []
	test_number = 1
	
	# Setup proxy configuration
	proxies = None
	if proxy_url:
		proxies = {
			'http': proxy_url,
			'https': proxy_url
		}
		print(f"[+] Using proxy: {proxy_url}")
		print("")
	
	print("--------------------------")
	print(f"{test_number}. Testing Staticmap API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for Staticmap API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Staticmap 			|| $2 per 1000 requests")
	elif b"PNG" in response.content:
		print("API key is not vulnerable for Staticmap API.")
		print("Reason: Manually check the "+url+" to view the reason.")
	else:
		print("API key is not vulnerable for Staticmap API.")
		print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Streetview API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for Streetview API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Streetview 			|| $7 per 1000 requests")
	elif b"PNG" in response.content:
		print("API key is not vulnerable for Streetview API.")
		print("Reason: Manually check the "+url+" to view the reason.")
	else:
		print("API key is not vulnerable for Streetview API.")
		print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Directions API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Directions API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Directions 			|| $5 per 1000 requests")
		vulnerable_apis.append("Directions (Advanced) 	|| $10 per 1000 requests")
	else:
		print("API key is not vulnerable for Directions API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Geocode API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Geocode API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Geocode 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Geocode API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Distance Matrix API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.6905615%2C-73.9976592%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626%7C40.659569%2C-73.933783%7C40.729029%2C-73.851524%7C40.6860072%2C-73.6334271%7C40.598566%2C-73.7527626&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Distance Matrix API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Distance Matrix 		|| $5 per 1000 elements")
		vulnerable_apis.append("Distance Matrix (Advanced) 	|| $10 per 1000 elements")
	else:
		print("API key is not vulnerable for Distance Matrix API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Find Place From Text API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum%20of%20Contemporary%20Art%20Australia&inputtype=textquery&fields=photos,formatted_address,name,rating,opening_hours,geometry&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies) 
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Find Place From Text API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Find Place From Text 		|| $17 per 1000 elements")
	else:
		print("API key is not vulnerable for Find Place From Text API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Autocomplete API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Autocomplete API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Autocomplete 			|| $2.83 per 1000 requests")
		vulnerable_apis.append("Autocomplete Per Session 	|| $17 per 1000 requests")
	else:
		print("API key is not vulnerable for Autocomplete API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Elevation API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Elevation API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Elevation 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Elevation API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Timezone API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("errorMessage") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Timezone API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Timezone 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Timezone API.")
		print("Reason: "+ response.json()["errorMessage"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Nearest Roads API")
	print("--------------------------")
	url = "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795|60.170879,24.942796|60.170877,24.942796&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Nearest Roads API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Nearest Roads 		|| $10 per 1000 requests")
	else:
		print("API key is not vulnerable for Nearest Roads API.")
		print("Reason: "+ response.json()["error"]["message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Geolocation API")
	print("--------------------------")
	url = "https://www.googleapis.com/geolocation/v1/geolocate?key="+apikey 
	postdata = {'considerIp': 'true'}
	response = requests.post(url, data=postdata, verify=False, proxies=proxies)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Geolocation API! Here is the PoC curl command which can be used from terminal:")
		print("curl -i -s -k  -X $'POST' -H $'Host: www.googleapis.com' -H $'Content-Length: 22' --data-binary $'{\"considerIp\": \"true\"}' $'"+url+"'")
		vulnerable_apis.append("Geolocation 			|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Geolocation API.")
		print("Reason: "+ response.json()["error"]["message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Route to Traveled API (Snap to Roads)")
	print("--------------------------")
	url = "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958|-35.28032,149.12907&interpolate=true&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Route to Traveled API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Route to Traveled 		|| $10 per 1000 requests")
	else:
		print("API key is not vulnerable for Route to Traveled API.")
		print("Reason: "+ response.json()["error"]["message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Speed Limit-Roads API")
	print("--------------------------")
	url = "https://roads.googleapis.com/v1/speedLimits?path=38.75807927603043,-9.03741754643809&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Speed Limit-Roads API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Speed Limit-Roads 		|| $20 per 1000 requests")
	else:
		print("API key is not vulnerable for Speed Limit-Roads API.")
		print("Reason: "+ response.json()["error"]["message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Place Details API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name,rating,formatted_phone_number&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Place Details API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Place Details 		|| $17 per 1000 requests")
	else:
		print("API key is not vulnerable for Place Details API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Nearby Search-Places API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&types=food&name=harbour&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Nearby Search-Places API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Nearby Search-Places		|| $32 per 1000 requests")
	else:
		print("API key is not vulnerable for Nearby Search-Places API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Text Search-Places API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Text Search-Places API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Text Search-Places 		|| $32 per 1000 requests")
	else:
		print("API key is not vulnerable for Text Search-Places API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Places Photo API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference=CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU&key="+apikey 
	response = requests.get(url, verify=False, proxies=proxies, allow_redirects=False)
	if response.status_code == 302:
		print("API key is \033[1;31;40mvulnerable\033[0m for Places Photo API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Places Photo 			|| $7 per 1000 requests")
	else:
		print("API key is not vulnerable for Places Photo API.")
		print("Reason: Verbose responses are not enabled for this API, cannot determine the reason.")

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing FCM API")
	print("--------------------------")
	url = "https://fcm.googleapis.com/fcm/send" 
	postdata = "{'registration_ids':['ABC']}"
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for FCM API! Here is the PoC curl command which can be used from terminal:")
		print("curl --header \"Authorization: key="+apikey+"\" --header Content-Type:\"application/json\" https://fcm.googleapis.com/fcm/send -d '{\"registration_ids\":[\"ABC\"]}'")
		vulnerable_apis.append("FCM Takeover 			|| https://abss.me/posts/fcm-takeover/")
	else:
		print("API key is not vulnerable for FCM API.")
		for lines in response.iter_lines():
			if(("TITLE") in str(lines)):
				print("Reason: "+str(lines).split("TITLE")[1].split("<")[0].replace(">",""))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Query Autocomplete API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=pizza+near%20Par&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.text.find("error_message") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Query Autocomplete API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Query Autocomplete 		|| $2.83 per 1000 requests")
	else:
		print("API key is not vulnerable for Query Autocomplete API.")
		print("Reason: "+ response.json()["error_message"])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Address Validation API")
	print("--------------------------")
	url = "https://addressvalidation.googleapis.com/v1:validateAddress?key="+apikey
	postdata = json.dumps({"address": {"regionCode": "US","addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA 94043"]}})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Address Validation API! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -d '{\"address\":{\"regionCode\":\"US\",\"addressLines\":[\"1600 Amphitheatre Pkwy\"]}}' '"+url+"'")
		vulnerable_apis.append("Address Validation 		|| $17 per 1000 requests")
	else:
		print("API key is not vulnerable for Address Validation API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Routes API (v2 - Compute Routes)")
	print("--------------------------")
	url = "https://routes.googleapis.com/directions/v2:computeRoutes?key="+apikey
	postdata = json.dumps({"origin":{"location":{"latLng":{"latitude": 37.419734,"longitude": -122.0827784}}},"destination":{"location":{"latLng":{"latitude": 37.417670,"longitude": -122.079595}}},"travelMode": "DRIVE"})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json','X-Goog-FieldMask':'routes.duration,routes.distanceMeters'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Routes API (v2)! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: routes.duration,routes.distanceMeters' -d '{\"origin\":{\"location\":{\"latLng\":{\"latitude\":37.419734,\"longitude\":-122.0827784}}},\"destination\":{\"location\":{\"latLng\":{\"latitude\":37.417670,\"longitude\":-122.079595}}},\"travelMode\":\"DRIVE\"}' '"+url+"'")
		vulnerable_apis.append("Routes API (Compute Routes) 	|| $5 per 1000 requests")
	else:
		print("API key is not vulnerable for Routes API (v2).")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Routes API (v2 - Route Matrix)")
	print("--------------------------")
	url = "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key="+apikey
	postdata = json.dumps({"origins":[{"waypoint":{"location":{"latLng":{"latitude":37.420761,"longitude":-122.081356}}}}],"destinations":[{"waypoint":{"location":{"latLng":{"latitude":37.420999,"longitude":-122.086894}}}}],"travelMode":"DRIVE"})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json','X-Goog-FieldMask':'originIndex,destinationIndex,duration,distanceMeters'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Routes API - Route Matrix (v2)! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: originIndex,destinationIndex,duration,distanceMeters' -d '{\"origins\":[{\"waypoint\":{\"location\":{\"latLng\":{\"latitude\":37.420761,\"longitude\":-122.081356}}}}],\"destinations\":[{\"waypoint\":{\"location\":{\"latLng\":{\"latitude\":37.420999,\"longitude\":-122.086894}}}}],\"travelMode\":\"DRIVE\"}' '"+url+"'")
		vulnerable_apis.append("Routes API (Route Matrix) 	|| $10 per 1000 elements")
	else:
		print("API key is not vulnerable for Routes API - Route Matrix (v2).")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Places API - Nearby Search (New)")
	print("--------------------------")
	url = "https://places.googleapis.com/v1/places:searchNearby?key="+apikey
	postdata = json.dumps({"includedTypes": ["restaurant"],"maxResultCount": 5,"locationRestriction": {"circle": {"center": {"latitude": 37.7937,"longitude": -122.3965},"radius": 500.0}}})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json','X-Goog-FieldMask':'places.displayName,places.id'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Places API - Nearby Search (New)! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: places.displayName' -d '{\"includedTypes\":[\"restaurant\"],\"maxResultCount\":5,\"locationRestriction\":{\"circle\":{\"center\":{\"latitude\":37.7937,\"longitude\":-122.3965},\"radius\":500.0}}}' '"+url+"'")
		vulnerable_apis.append("Places API - Nearby Search (New) || $32 per 1000 requests")
	else:
		print("API key is not vulnerable for Places API - Nearby Search (New).")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Places API - Text Search (New)")
	print("--------------------------")
	url = "https://places.googleapis.com/v1/places:searchText?key="+apikey
	postdata = json.dumps({"textQuery": "Spicy Vegetarian Food in Sydney, Australia"})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json','X-Goog-FieldMask':'places.displayName,places.formattedAddress'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Places API - Text Search (New)! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -H 'X-Goog-FieldMask: places.displayName' -d '{\"textQuery\":\"restaurants in Sydney\"}' '"+url+"'")
		vulnerable_apis.append("Places API - Text Search (New) 	|| $32 per 1000 requests")
	else:
		print("API key is not vulnerable for Places API - Text Search (New).")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Air Quality API")
	print("--------------------------")
	url = "https://airquality.googleapis.com/v1/currentConditions:lookup?key="+apikey
	postdata = json.dumps({"location": {"latitude": 37.419734,"longitude": -122.0827784}})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Air Quality API! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -d '{\"location\":{\"latitude\":37.419734,\"longitude\":-122.0827784}}' '"+url+"'")
		vulnerable_apis.append("Air Quality API 		|| Contact Google for pricing")
	else:
		print("API key is not vulnerable for Air Quality API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Pollen API")
	print("--------------------------")
	url = "https://pollen.googleapis.com/v1/forecast:lookup?key="+apikey+"&location.latitude=37.419734&location.longitude=-122.0827784&days=1"
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Pollen API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Pollen API 			|| Contact Google for pricing")
	else:
		print("API key is not vulnerable for Pollen API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Solar API")
	print("--------------------------")
	url = "https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=37.4450&location.longitude=-122.1390&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Solar API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Solar API 			|| Contact Google for pricing")
	else:
		print("API key is not vulnerable for Solar API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Playable Locations API")
	print("--------------------------")
	url = "https://playablelocations.googleapis.com/v3:samplePlayableLocations?key="+apikey
	postdata = json.dumps({"area_filter": {"s2_cell_id": 7715420662885515264},"criteria": [{"gameObjectType": 1,"filter": {"maxLocationCount": 4,"includedTypes": ["food_and_drink"]}}]})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Playable Locations API! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -d '{\"area_filter\":{\"s2_cell_id\":7715420662885515264},\"criteria\":[{\"gameObjectType\":1,\"filter\":{\"maxLocationCount\":4,\"includedTypes\":[\"food_and_drink\"]}}]}' '"+url+"'")
		vulnerable_apis.append("Playable Locations API 		|| Contact Google for pricing")
	else:
		print("API key is not vulnerable for Playable Locations API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Aerial View API")
	print("--------------------------")
	url = "https://aerialview.googleapis.com/v1/videos:renderVideo?key="+apikey
	postdata = json.dumps({"address": "1600 Amphitheatre Parkway, Mountain View, CA 94043"})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type':'application/json'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Aerial View API! Here is the PoC curl command which can be used from terminal:")
		print("curl -X POST -H 'Content-Type: application/json' -d '{\"address\":\"1600 Amphitheatre Parkway, Mountain View, CA 94043\"}' '"+url+"'")
		vulnerable_apis.append("Aerial View API 		|| Contact Google for pricing")
	else:
		print("API key is not vulnerable for Aerial View API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Map Tiles API")
	print("--------------------------")
	url = "https://tile.googleapis.com/v1/2dtiles/2/2/2?session=&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200:
		print("API key is \033[1;31;40mvulnerable\033[0m for Map Tiles API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Map Tiles API 			|| $2 per 1000 requests")
	else:
		print("API key is not vulnerable for Map Tiles API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except:
				print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Maps Embed API")
	print("--------------------------")
	url = "https://www.google.com/maps/embed/v1/place?key="+apikey+"&q=Space+Needle,Seattle+WA"
	response = requests.get(url, verify=False, proxies=proxies, allow_redirects=False)
	if response.status_code == 200 or response.status_code == 302:
		print("API key is \033[1;31;40mvulnerable\033[0m for Maps Embed API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Maps Embed API 			|| Free (with restrictions)")
	else:
		print("API key is not vulnerable for Maps Embed API.")
		print("Reason: "+ str(response.content))

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Maps JavaScript API")
	print("--------------------------")
	url = "https://maps.googleapis.com/maps/api/js?key="+apikey+"&callback=initMap"
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("InvalidKeyMapError") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Maps JavaScript API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Maps JavaScript API 		|| $7 per 1000 requests")
	else:
		print("API key is not vulnerable for Maps JavaScript API.")
		if response.text.find("InvalidKeyMapError") >= 0:
			print("Reason: Invalid API key or key restrictions")
		else:
			print("Reason: "+ str(response.content)[:200])

	# ==========================================================================
	# Modern Google AI & Cloud Services (Gemini, Vision, NLP, Translation, etc.)
	# ==========================================================================
	print("\n" + "=" * 60)
	print("  Modern Google AI & Cloud Services")
	print("=" * 60)

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Gemini API - List Models (Generative Language)")
	print("--------------------------")
	url = "https://generativelanguage.googleapis.com/v1beta/models?key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("\"models\"") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Gemini API (List Models)! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Gemini API (List Models) 	|| Probe - enumerates accessible Gemini models")
	else:
		print("API key is not vulnerable for Gemini API (List Models).")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Gemini API - generateContent (gemini-2.0-flash)")
	print("--------------------------")
	gemini_model = "gemini-2.0-flash"
	url = f"https://generativelanguage.googleapis.com/v1beta/models/{gemini_model}:generateContent?key={apikey}"
	postdata = json.dumps({"contents": [{"parts": [{"text": "Reply with one word: ok"}]}]})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	if response.status_code == 200 and response.text.find("\"candidates\"") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Gemini API (generateContent)! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"contents\":[{{\"parts\":[{{\"text\":\"Hello\"}}]}}]}}' '{url}'")
		vulnerable_apis.append(f"Gemini API ({gemini_model}) 	|| ~$0.10/$0.40 per 1M tokens (input/output) - HIGH ABUSE RISK")
	else:
		# Retry with gemini-1.5-flash as fallback (older keys/projects)
		fallback_model = "gemini-1.5-flash"
		fallback_url = f"https://generativelanguage.googleapis.com/v1beta/models/{fallback_model}:generateContent?key={apikey}"
		fallback_resp = requests.post(fallback_url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
		if fallback_resp.status_code == 200 and fallback_resp.text.find("\"candidates\"") >= 0:
			print("API key is \033[1;31;40mvulnerable\033[0m for Gemini API (generateContent - gemini-1.5-flash fallback)! Here is the PoC curl command:")
			print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"contents\":[{{\"parts\":[{{\"text\":\"Hello\"}}]}}]}}' '{fallback_url}'")
			vulnerable_apis.append(f"Gemini API ({fallback_model}) 	|| ~$0.075/$0.30 per 1M tokens (input/output) - HIGH ABUSE RISK")
		else:
			print("API key is not vulnerable for Gemini API (generateContent).")
			if response.text.find("error") >= 0:
				try:
					print("Reason: "+ response.json()["error"]["message"])
				except Exception:
					print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Cloud Vision API")
	print("--------------------------")
	url = "https://vision.googleapis.com/v1/images:annotate?key="+apikey
	postdata = json.dumps({"requests": [{"image": {"source": {"imageUri": "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"}}, "features": [{"type": "LABEL_DETECTION", "maxResults": 1}]}]})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	if response.status_code == 200 and response.text.find("\"responses\"") >= 0 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Cloud Vision API! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"requests\":[{{\"image\":{{\"source\":{{\"imageUri\":\"https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png\"}}}},\"features\":[{{\"type\":\"LABEL_DETECTION\"}}]}}]}}' '{url}'")
		vulnerable_apis.append("Cloud Vision API 		|| $1.50 per 1000 requests (LABEL_DETECTION)")
	else:
		print("API key is not vulnerable for Cloud Vision API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Cloud Natural Language API")
	print("--------------------------")
	url = "https://language.googleapis.com/v1/documents:analyzeSentiment?key="+apikey
	postdata = json.dumps({"document": {"type": "PLAIN_TEXT", "content": "I love programming."}, "encodingType": "UTF8"})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	if response.status_code == 200 and response.text.find("documentSentiment") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Cloud Natural Language API! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"document\":{{\"type\":\"PLAIN_TEXT\",\"content\":\"Hello\"}},\"encodingType\":\"UTF8\"}}' '{url}'")
		vulnerable_apis.append("Cloud Natural Language API 	|| $1 per 1000 records (Sentiment)")
	else:
		print("API key is not vulnerable for Cloud Natural Language API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Cloud Translation API (v2)")
	print("--------------------------")
	url = "https://translation.googleapis.com/language/translate/v2?key="+apikey+"&q=hello&target=es&source=en"
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("translatedText") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Cloud Translation API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Cloud Translation API 		|| $20 per 1M characters (Basic)")
	else:
		print("API key is not vulnerable for Cloud Translation API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Cloud Text-to-Speech API")
	print("--------------------------")
	url = "https://texttospeech.googleapis.com/v1/voices?key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("\"voices\"") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Cloud Text-to-Speech API (voices listing)! Here is the PoC link which can be used directly via browser:")
		print(url)
		print("PoC (synthesize): curl -X POST -H 'Content-Type: application/json' -d '{\"input\":{\"text\":\"Hello\"},\"voice\":{\"languageCode\":\"en-US\"},\"audioConfig\":{\"audioEncoding\":\"MP3\"}}' 'https://texttospeech.googleapis.com/v1/text:synthesize?key="+apikey+"'")
		vulnerable_apis.append("Cloud Text-to-Speech API 	|| $4/1M chars (Standard), $16/1M (WaveNet/Neural2)")
	else:
		print("API key is not vulnerable for Cloud Text-to-Speech API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Cloud Speech-to-Text API")
	print("--------------------------")
	url = "https://speech.googleapis.com/v1/speech:recognize?key="+apikey
	postdata = json.dumps({"config": {"encoding": "LINEAR16", "sampleRateHertz": 16000, "languageCode": "en-US"}, "audio": {"uri": "gs://cloud-samples-tests/speech/brooklyn.flac"}})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	# 200 = full success; 403/PERMISSION_DENIED on bucket but 200-style API auth = key works.
	# Distinguish API key invalidity (API_KEY_INVALID / API not enabled) from data errors.
	resp_text = response.text
	api_key_blocked = ("API_KEY_INVALID" in resp_text) or ("API key not valid" in resp_text) or ("has not been used" in resp_text) or ("PERMISSION_DENIED" in resp_text and "Cloud Speech" in resp_text)
	if response.status_code == 200 or (not api_key_blocked and response.status_code in (400, 403) and "INVALID_ARGUMENT" in resp_text):
		print("API key is \033[1;31;40mvulnerable\033[0m for Cloud Speech-to-Text API! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"config\":{{\"encoding\":\"LINEAR16\",\"sampleRateHertz\":16000,\"languageCode\":\"en-US\"}},\"audio\":{{\"uri\":\"gs://cloud-samples-tests/speech/brooklyn.flac\"}}}}' '{url}'")
		vulnerable_apis.append("Cloud Speech-to-Text API 	|| $0.016 per minute (~$0.96 per hour)")
	else:
		print("API key is not vulnerable for Cloud Speech-to-Text API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Cloud Video Intelligence API")
	print("--------------------------")
	url = "https://videointelligence.googleapis.com/v1/videos:annotate?key="+apikey
	postdata = json.dumps({"inputUri": "gs://cloud-samples-data/video/cat.mp4", "features": ["LABEL_DETECTION"]})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	if response.status_code == 200 and response.text.find("\"name\"") >= 0 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Cloud Video Intelligence API! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"inputUri\":\"gs://cloud-samples-data/video/cat.mp4\",\"features\":[\"LABEL_DETECTION\"]}}' '{url}'")
		vulnerable_apis.append("Cloud Video Intelligence API 	|| $0.10 per minute (LABEL_DETECTION)")
	else:
		print("API key is not vulnerable for Cloud Video Intelligence API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing YouTube Data API v3")
	print("--------------------------")
	url = "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&maxResults=1&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("\"items\"") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for YouTube Data API v3! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("YouTube Data API v3 		|| Free (10K units/day quota) - data scraping abuse")
	else:
		print("API key is not vulnerable for YouTube Data API v3.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Safe Browsing API v4")
	print("--------------------------")
	url = "https://safebrowsing.googleapis.com/v4/threatMatches:find?key="+apikey
	postdata = json.dumps({
		"client": {"clientId": "evaupgraded", "clientVersion": "1.0"},
		"threatInfo": {
			"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
			"platformTypes": ["ANY_PLATFORM"],
			"threatEntryTypes": ["URL"],
			"threatEntries": [{"url": "http://malware.testing.google.test/testing/malware/"}]
		}
	})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	if response.status_code == 200 and response.text.find("error") < 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Safe Browsing API v4! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"client\":{{\"clientId\":\"x\",\"clientVersion\":\"1\"}},\"threatInfo\":{{\"threatTypes\":[\"MALWARE\"],\"platformTypes\":[\"ANY_PLATFORM\"],\"threatEntryTypes\":[\"URL\"],\"threatEntries\":[{{\"url\":\"http://example.com\"}}]}}}}' '{url}'")
		vulnerable_apis.append("Safe Browsing API v4 		|| Free (quota-limited) - info disclosure / quota abuse")
	else:
		print("API key is not vulnerable for Safe Browsing API v4.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Identity Toolkit / Firebase Auth (accounts:signUp) [CRITICAL]")
	print("--------------------------")
	url = "https://identitytoolkit.googleapis.com/v1/accounts:signUp?key="+apikey
	postdata = json.dumps({"returnSecureToken": True})
	response = requests.post(url, data=postdata, verify=False, proxies=proxies, headers={'Content-Type': 'application/json'})
	# 200 + idToken => anonymous signup enabled (very dangerous)
	# 400 + OPERATION_NOT_ALLOWED but no API_KEY_INVALID => key works, but anonymous auth disabled (still exposed API)
	if response.status_code == 200 and response.text.find("idToken") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Identity Toolkit (Anonymous SignUp ENABLED - CRITICAL)! Here is the PoC curl command which can be used from terminal:")
		print(f"curl -X POST -H 'Content-Type: application/json' -d '{{\"returnSecureToken\":true}}' '{url}'")
		vulnerable_apis.append("Firebase Auth - Anonymous SignUp || \033[1;31mCRITICAL\033[0m - Account creation abuse / DB access via tokens")
	elif response.status_code == 400 and ("OPERATION_NOT_ALLOWED" in response.text or "ADMIN_ONLY_OPERATION" in response.text):
		print("API key is \033[1;31;40mvulnerable\033[0m for Identity Toolkit endpoint (key accepted, anonymous signup disabled)!")
		print("PoC (email/password signup): curl -X POST -H 'Content-Type: application/json' -d '{\"email\":\"test@example.com\",\"password\":\"Passw0rd!\",\"returnSecureToken\":true}' '"+url+"'")
		vulnerable_apis.append("Firebase Auth - Identity Toolkit || Key accepted; try email/password signup, sendOobCode, etc.")
	else:
		print("API key is not vulnerable for Identity Toolkit / Firebase Auth.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Custom Search API")
	print("--------------------------")
	# Use Google's public example search engine id for the probe
	example_cx = "017576662512468239146:omuauf_lfve"
	url = f"https://www.googleapis.com/customsearch/v1?key={apikey}&cx={example_cx}&q=test&num=1"
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and (response.text.find("\"items\"") >= 0 or response.text.find("\"searchInformation\"") >= 0):
		print("API key is \033[1;31;40mvulnerable\033[0m for Custom Search API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Custom Search JSON API 		|| $5 per 1000 queries (after 100/day free)")
	else:
		print("API key is not vulnerable for Custom Search API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	test_number += 1
	print("\n--------------------------")
	print(f"{test_number}. Testing Google Books API")
	print("--------------------------")
	url = "https://www.googleapis.com/books/v1/volumes?q=python&maxResults=1&key="+apikey
	response = requests.get(url, verify=False, proxies=proxies)
	if response.status_code == 200 and response.text.find("\"items\"") >= 0:
		print("API key is \033[1;31;40mvulnerable\033[0m for Google Books API! Here is the PoC link which can be used directly via browser:")
		print(url)
		vulnerable_apis.append("Google Books API 		|| Free (quota-limited)")
	else:
		print("API key is not vulnerable for Google Books API.")
		if response.text.find("error") >= 0:
			try:
				print("Reason: "+ response.json()["error"]["message"])
			except Exception:
				print("Reason: "+ str(response.content)[:200])

	print_single_table(apikey, vulnerable_apis, test_number)
	print("Reference for up-to-date pricing:")
	print("  Maps:        https://cloud.google.com/maps-platform/pricing")
	print("  GMP Billing: https://developers.google.com/maps/billing/gmp-billing")
	print("  Gemini:      https://ai.google.dev/pricing")
	print("  Vertex AI:   https://cloud.google.com/vertex-ai/pricing")
	print("  Vision:      https://cloud.google.com/vision/pricing")
	print("  NL API:      https://cloud.google.com/natural-language/pricing")
	print("  Translate:   https://cloud.google.com/translate/pricing")
	print("  TTS / STT:   https://cloud.google.com/text-to-speech/pricing | https://cloud.google.com/speech-to-text/pricing")
	print("  Video AI:    https://cloud.google.com/video-intelligence/pricing")
	print("  Firebase:    https://firebase.google.com/pricing")
	print("-------------------------------------------------------------")
	jsapi = input("Do you want to conduct manual tests for Javascript API? (Will need manual confirmation + file creation) (Y/N): ")
	if jsapi == "Y" or jsapi == "y":
		f = open("jsapi_test.html","w+")
		f.write('<!DOCTYPE html><html><head><script src="https://maps.googleapis.com/maps/api/js?key='+apikey+'&callback=initMap&libraries=&v=weekly" defer></script><style type="text/css">#map{height:100%;}html,body{height:100%;margin:0;padding:0;}</style><script>let map;function initMap(){map=new google.maps.Map(document.getElementById("map"),{center:{lat:-34.397,lng:150.644},zoom:8,});}</script></head><body><div id="map"></div></body></html>')
		print("jsapi_test.html file is created for manual confirmation. Open it at your browser and observe whether the map is successfully loaded or not.") 
		f.close()
		print("If you see 'Sorry! Something went wrong.' error on the page, it means that API key is not allowed to be used at JavaScript API.")
		result = input("Press enter again for deletion of jsapi_test.html file automatically after manual confirmation is conducted.")
		os.remove("jsapi_test.html")
	print("-------------------------------------------------------------")
	print("Operation is over. Thanks for using EVA Upgraded - G-Maps API Scanner by Bar Hajby!")
	return True


def scan_gmaps_batch(api_keys: List[str], proxy_url=None):
	"""Scan multiple API keys and generate a comparison table."""
	# Setup proxy
	proxies = None
	if proxy_url:
		proxies = {'http': proxy_url, 'https': proxy_url}
		print(f"[+] Using proxy: {proxy_url}\n")
	
	print(f"[+] Batch mode: Testing {len(api_keys)} API keys against 46 endpoints (Maps + AI/Cloud)")
	print(f"[+] Strategy: Test each endpoint against all keys, then move to next endpoint\n")
	
	# Results dictionary: {api_name: {api_key: is_vulnerable}}
	results = defaultdict(lambda: defaultdict(bool))
	
	test_number = 1
	
	# Test 1: Staticmap API
	print("--------------------------")
	print(f"{test_number}. Testing Staticmap API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = f"https://maps.googleapis.com/maps/api/staticmap?center=45%2C10&zoom=7&size=400x400&key={apikey}"
			response = requests.get(url, verify=False, proxies=proxies, timeout=10)
			if response.status_code == 200:
				results["Staticmap API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	test_number += 1
	# Test 2: Streetview API
	print(f"\n--------------------------")
	print(f"{test_number}. Testing Streetview API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = f"https://maps.googleapis.com/maps/api/streetview?size=400x400&location=40.720032,-73.988354&fov=90&heading=235&pitch=10&key={apikey}"
			response = requests.get(url, verify=False, proxies=proxies, timeout=10)
			if response.status_code == 200:
				results["Streetview API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	test_number += 1
	# Test 3: Directions API
	print(f"\n--------------------------")
	print(f"{test_number}. Testing Directions API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = f"https://maps.googleapis.com/maps/api/directions/json?origin=Disneyland&destination=Universal+Studios+Hollywood4&key={apikey}"
			response = requests.get(url, verify=False, proxies=proxies, timeout=10)
			if response.text.find("error_message") < 0:
				results["Directions API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	test_number += 1
	# Test 4: Geocode API
	print(f"\n--------------------------")
	print(f"{test_number}. Testing Geocode API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = f"https://maps.googleapis.com/maps/api/geocode/json?latlng=40,30&key={apikey}"
			response = requests.get(url, verify=False, proxies=proxies, timeout=10)
			if response.text.find("error_message") < 0:
				results["Geocode API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	test_number += 1
	# Test 5: Distance Matrix API
	print(f"\n--------------------------")
	print(f"{test_number}. Testing Distance Matrix API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = f"https://maps.googleapis.com/maps/api/distancematrix/json?units=imperial&origins=40.6655101,-73.89188969999998&destinations=40.6905615%2C-73.9976592&key={apikey}"
			response = requests.get(url, verify=False, proxies=proxies, timeout=10)
			if response.text.find("error_message") < 0:
				results["Distance Matrix API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	# GET-based endpoint tests using error-string detection
	# Format: (test_number, api_name, url_template_with_{}, error_marker_string)
	get_apis_to_test = [
		(6, "Find Place From Text API", "https://maps.googleapis.com/maps/api/place/findplacefromtext/json?input=Museum&inputtype=textquery&fields=name&key={}", "error_message"),
		(7, "Autocomplete API", "https://maps.googleapis.com/maps/api/place/autocomplete/json?input=Bingh&types=%28cities%29&key={}", "error_message"),
		(8, "Elevation API", "https://maps.googleapis.com/maps/api/elevation/json?locations=39.7391536,-104.9847034&key={}", "error_message"),
		(9, "Timezone API", "https://maps.googleapis.com/maps/api/timezone/json?location=39.6034810,-119.6822510&timestamp=1331161200&key={}", "errorMessage"),
		(10, "Nearest Roads API", "https://roads.googleapis.com/v1/nearestRoads?points=60.170880,24.942795&key={}", "error"),
		(11, "Snap to Roads API", "https://roads.googleapis.com/v1/snapToRoads?path=-35.27801,149.12958&key={}", "error"),
		(12, "Speed Limit-Roads API", "https://roads.googleapis.com/v1/speedLimits?path=38.7580,-9.0374&key={}", "error"),
		(13, "Place Details API", "https://maps.googleapis.com/maps/api/place/details/json?place_id=ChIJN1t_tDeuEmsRUsoyG83frY4&fields=name&key={}", "error_message"),
		(14, "Nearby Search-Places API", "https://maps.googleapis.com/maps/api/place/nearbysearch/json?location=-33.8670522,151.1957362&radius=100&key={}", "error_message"),
		(15, "Text Search-Places API", "https://maps.googleapis.com/maps/api/place/textsearch/json?query=restaurants+in+Sydney&key={}", "error_message"),
		(16, "Query Autocomplete API", "https://maps.googleapis.com/maps/api/place/queryautocomplete/json?input=pizza&key={}", "error_message"),
		(17, "Pollen API", "https://pollen.googleapis.com/v1/forecast:lookup?key={}&location.latitude=37.419734&location.longitude=-122.0827784&days=1", "error"),
		(18, "Solar API", "https://solar.googleapis.com/v1/buildingInsights:findClosest?location.latitude=37.4450&location.longitude=-122.1390&key={}", "error"),
	]
	
	for test_num, api_name, url_template, error_key in get_apis_to_test:
		print(f"\n--------------------------")
		print(f"{test_num}. Testing {api_name} across all keys")
		print("--------------------------")
		for idx, apikey in enumerate(api_keys, 1):
			try:
				url = url_template.format(apikey)
				response = requests.get(url, verify=False, proxies=proxies, timeout=10)
				if response.text.find(error_key) < 0:
					results[api_name][apikey] = True
					print(f"  Key {idx}: ✓ VULNERABLE")
				else:
					print(f"  Key {idx}: ✗ Safe")
			except Exception as e:
				print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	# Status-code-based GET endpoint tests (success when status code matches)
	# Format: (test_number, api_name, url_template, expected_status_codes_tuple)
	status_apis_to_test = [
		(19, "Map Tiles API", "https://tile.googleapis.com/v1/2dtiles/2/2/2?session=&key={}", (200,)),
		(20, "Maps Embed API", "https://www.google.com/maps/embed/v1/place?key={}&q=Space+Needle,Seattle+WA", (200, 302)),
	]
	
	for test_num, api_name, url_template, ok_codes in status_apis_to_test:
		print(f"\n--------------------------")
		print(f"{test_num}. Testing {api_name} across all keys")
		print("--------------------------")
		for idx, apikey in enumerate(api_keys, 1):
			try:
				url = url_template.format(apikey)
				response = requests.get(url, verify=False, proxies=proxies, timeout=10, allow_redirects=False)
				if response.status_code in ok_codes:
					results[api_name][apikey] = True
					print(f"  Key {idx}: ✓ VULNERABLE")
				else:
					print(f"  Key {idx}: ✗ Safe")
			except Exception as e:
				print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	# POST-based endpoint tests
	# Format: (test_number, api_name, url_template, json_body, extra_headers, success_marker, error_marker)
	post_apis_to_test = [
		(21, "Geolocation API", "https://www.googleapis.com/geolocation/v1/geolocate?key={}",
			{"considerIp": "true"}, {}, "location", "error"),
		(22, "Address Validation API", "https://addressvalidation.googleapis.com/v1:validateAddress?key={}",
			{"address": {"regionCode": "US", "addressLines": ["1600 Amphitheatre Pkwy, Mountain View, CA 94043"]}}, {}, "result", "error"),
		(23, "Routes API (Compute Routes v2)", "https://routes.googleapis.com/directions/v2:computeRoutes?key={}",
			{"origin": {"location": {"latLng": {"latitude": 37.419734, "longitude": -122.0827784}}},
			 "destination": {"location": {"latLng": {"latitude": 37.417670, "longitude": -122.079595}}},
			 "travelMode": "DRIVE"},
			{"X-Goog-FieldMask": "routes.duration,routes.distanceMeters"}, "routes", "error"),
		(24, "Routes API (Route Matrix v2)", "https://routes.googleapis.com/distanceMatrix/v2:computeRouteMatrix?key={}",
			{"origins": [{"waypoint": {"location": {"latLng": {"latitude": 37.420761, "longitude": -122.081356}}}}],
			 "destinations": [{"waypoint": {"location": {"latLng": {"latitude": 37.420999, "longitude": -122.086894}}}}],
			 "travelMode": "DRIVE"},
			{"X-Goog-FieldMask": "originIndex,destinationIndex,duration,distanceMeters"}, "duration", "error"),
		(25, "Places API - Nearby Search (New)", "https://places.googleapis.com/v1/places:searchNearby?key={}",
			{"includedTypes": ["restaurant"], "maxResultCount": 5,
			 "locationRestriction": {"circle": {"center": {"latitude": 37.7937, "longitude": -122.3965}, "radius": 500.0}}},
			{"X-Goog-FieldMask": "places.displayName,places.id"}, "places", "error"),
		(26, "Places API - Text Search (New)", "https://places.googleapis.com/v1/places:searchText?key={}",
			{"textQuery": "Spicy Vegetarian Food in Sydney, Australia"},
			{"X-Goog-FieldMask": "places.displayName,places.formattedAddress"}, "places", "error"),
		(27, "Air Quality API", "https://airquality.googleapis.com/v1/currentConditions:lookup?key={}",
			{"location": {"latitude": 37.419734, "longitude": -122.0827784}}, {}, "indexes", "error"),
		(28, "Aerial View API", "https://aerialview.googleapis.com/v1/videos:renderVideo?key={}",
			{"address": "1600 Amphitheatre Parkway, Mountain View, CA 94043"}, {}, "state", "error"),
		(29, "Playable Locations API", "https://playablelocations.googleapis.com/v3:samplePlayableLocations?key={}",
			{"area_filter": {"s2_cell_id": 7715420662885515264},
			 "criteria": [{"gameObjectType": 1, "filter": {"maxLocationCount": 4, "includedTypes": ["food_and_drink"]}}]},
			{}, "locationsPerGameObjectType", "error"),
		# Modern AI & Cloud Services
		(30, "Gemini API (gemini-2.0-flash)", "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key={}",
			{"contents": [{"parts": [{"text": "Reply with one word: ok"}]}]}, {}, "candidates", "error"),
		(31, "Cloud Vision API", "https://vision.googleapis.com/v1/images:annotate?key={}",
			{"requests": [{"image": {"source": {"imageUri": "https://www.google.com/images/branding/googlelogo/2x/googlelogo_color_272x92dp.png"}},
				"features": [{"type": "LABEL_DETECTION", "maxResults": 1}]}]}, {}, "responses", "error"),
		(32, "Cloud Natural Language API", "https://language.googleapis.com/v1/documents:analyzeSentiment?key={}",
			{"document": {"type": "PLAIN_TEXT", "content": "I love programming."}, "encodingType": "UTF8"},
			{}, "documentSentiment", "error"),
		(33, "Cloud Speech-to-Text API", "https://speech.googleapis.com/v1/speech:recognize?key={}",
			{"config": {"encoding": "LINEAR16", "sampleRateHertz": 16000, "languageCode": "en-US"},
			 "audio": {"uri": "gs://cloud-samples-tests/speech/brooklyn.flac"}}, {}, "results", "API_KEY_INVALID"),
		(34, "Cloud Video Intelligence API", "https://videointelligence.googleapis.com/v1/videos:annotate?key={}",
			{"inputUri": "gs://cloud-samples-data/video/cat.mp4", "features": ["LABEL_DETECTION"]}, {}, "name", "error"),
		(35, "Safe Browsing API v4", "https://safebrowsing.googleapis.com/v4/threatMatches:find?key={}",
			{"client": {"clientId": "evaupgraded", "clientVersion": "1.0"},
			 "threatInfo": {"threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"], "platformTypes": ["ANY_PLATFORM"],
				"threatEntryTypes": ["URL"], "threatEntries": [{"url": "http://malware.testing.google.test/testing/malware/"}]}},
			{}, "{", "error"),
		(36, "Identity Toolkit / Firebase Auth (signUp) [CRITICAL]",
			"https://identitytoolkit.googleapis.com/v1/accounts:signUp?key={}",
			{"returnSecureToken": True}, {}, "idToken", "API_KEY_INVALID"),
	]
	
	for test_num, api_name, url_template, body, extra_headers, success_marker, error_marker in post_apis_to_test:
		print(f"\n--------------------------")
		print(f"{test_num}. Testing {api_name} across all keys")
		print("--------------------------")
		for idx, apikey in enumerate(api_keys, 1):
			try:
				url = url_template.format(apikey)
				headers = {'Content-Type': 'application/json'}
				headers.update(extra_headers)
				response = requests.post(url, data=json.dumps(body), verify=False, proxies=proxies,
					timeout=15, headers=headers)
				# Vulnerable if: 200 status AND success_marker present AND no fatal error marker
				is_vuln = (response.status_code == 200 and success_marker in response.text
					and error_marker not in response.text)
				# Identity Toolkit special-case: 400 OPERATION_NOT_ALLOWED means the key was accepted
				if not is_vuln and "Identity Toolkit" in api_name and response.status_code == 400 \
					and ("OPERATION_NOT_ALLOWED" in response.text or "ADMIN_ONLY_OPERATION" in response.text):
					is_vuln = True
				if is_vuln:
					results[api_name][apikey] = True
					print(f"  Key {idx}: ✓ VULNERABLE")
				else:
					print(f"  Key {idx}: ✗ Safe")
			except Exception as e:
				print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	# Modern GET-based AI/Cloud endpoint tests
	modern_get_apis = [
		(37, "Gemini API (List Models)", "https://generativelanguage.googleapis.com/v1beta/models?key={}", "models"),
		(38, "Cloud Translation API (v2)", "https://translation.googleapis.com/language/translate/v2?key={}&q=hello&target=es&source=en", "translatedText"),
		(39, "Cloud Text-to-Speech API", "https://texttospeech.googleapis.com/v1/voices?key={}", "voices"),
		(40, "YouTube Data API v3", "https://www.googleapis.com/youtube/v3/search?part=snippet&q=test&maxResults=1&key={}", "items"),
		(41, "Custom Search JSON API", "https://www.googleapis.com/customsearch/v1?key={}&cx=017576662512468239146:omuauf_lfve&q=test&num=1", "searchInformation"),
		(42, "Google Books API", "https://www.googleapis.com/books/v1/volumes?q=python&maxResults=1&key={}", "items"),
	]
	
	for test_num, api_name, url_template, success_marker in modern_get_apis:
		print(f"\n--------------------------")
		print(f"{test_num}. Testing {api_name} across all keys")
		print("--------------------------")
		for idx, apikey in enumerate(api_keys, 1):
			try:
				url = url_template.format(apikey)
				response = requests.get(url, verify=False, proxies=proxies, timeout=10)
				if response.status_code == 200 and success_marker in response.text:
					results[api_name][apikey] = True
					print(f"  Key {idx}: ✓ VULNERABLE")
				else:
					print(f"  Key {idx}: ✗ Safe")
			except Exception as e:
				print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	# Special handlers: FCM (custom auth header) and Places Photo (302 redirect detection)
	test_num = 43
	print(f"\n--------------------------")
	print(f"{test_num}. Testing FCM API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = "https://fcm.googleapis.com/fcm/send"
			postdata = "{'registration_ids':['ABC']}"
			response = requests.post(url, data=postdata, verify=False, proxies=proxies, timeout=10,
				headers={'Content-Type': 'application/json', 'Authorization': 'key=' + apikey})
			if response.status_code == 200:
				results["FCM API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	test_num = 44
	print(f"\n--------------------------")
	print(f"{test_num}. Testing Places Photo API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = ("https://maps.googleapis.com/maps/api/place/photo?maxwidth=400&photoreference="
				"CnRtAAAATLZNl354RwP_9UKbQ_5Psy40texXePv4oAlgP4qNEkdIrkyse7rPXYGd9D_Uj1rVsQdWT4oRz4QrYAJNpFX7rzqqMlZw2h2E2y5IKMUZ7ouD_SlcHxYq1yL4KbKUv3qtWgTK0A6QbGh87GB3sscrHRIQiG2RrmU_jF4tENr9wGS_YxoUSSDrYjWmrNfeEHSGSc3FyhNLlBU"
				f"&key={apikey}")
			response = requests.get(url, verify=False, proxies=proxies, timeout=10, allow_redirects=False)
			if response.status_code == 302:
				results["Places Photo API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	test_num = 45
	print(f"\n--------------------------")
	print(f"{test_num}. Testing Maps JavaScript API across all keys")
	print("--------------------------")
	for idx, apikey in enumerate(api_keys, 1):
		try:
			url = f"https://maps.googleapis.com/maps/api/js?key={apikey}&callback=initMap"
			response = requests.get(url, verify=False, proxies=proxies, timeout=10)
			if response.status_code == 200 and "InvalidKeyMapError" not in response.text:
				results["Maps JavaScript API"][apikey] = True
				print(f"  Key {idx}: ✓ VULNERABLE")
			else:
				print(f"  Key {idx}: ✗ Safe")
		except Exception as e:
			print(f"  Key {idx}: ✗ Error - {str(e)[:50]}")
	
	# Print results table
	print_results_table(results, api_keys)
	
	print("Operation is over. Thanks for using EVA Upgraded - G-Maps API Scanner by Bar Hajby!")
	return results


def main() -> None:
	warnings.filterwarnings("ignore")
	
	parser = argparse.ArgumentParser(
		description='EVA Upgraded - Google API Scanner by Bar Hajby (Maps + Gemini AI + Cloud AI/ML + Firebase Auth) - 46 endpoint checks',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog='''
Examples:
  # Single key scan (tests all 46 endpoints)
  python eva_gmaps_scanner.py --api-key YOUR_KEY
  python eva_gmaps_scanner.py -a YOUR_KEY -p http://127.0.0.1:8080

  # Batch scan (multiple keys)
  python eva_gmaps_scanner.py --list keys.txt
  python eva_gmaps_scanner.py -l keys.txt -p

  # File format for batch mode (keys.txt):
  AIzaSyD...
  AIzaSyE...
  AIzaSyF...
  # OR comma-separated: AIzaSyD..., AIzaSyE..., AIzaSyF...

Coverage: Maps (32) + Google AI / Gemini (2) + Cloud AI/ML (6) + Identity/Data (6).
		'''
	)
	
	parser.add_argument(
		'-a', '--api-key',
		type=str,
		help='Single Google API key (AIzaSy...) to test against all 46 endpoints'
	)
	
	parser.add_argument(
		'-l', '--list',
		type=str,
		help='File containing multiple API keys (newline or comma separated)'
	)
	
	parser.add_argument(
		'-p', '--proxy',
		type=str,
		nargs='?',
		const='http://127.0.0.1:8080',
		default=None,
		help='Proxy URL (default: http://127.0.0.1:8080 if flag is used without value)'
	)
	
	args = parser.parse_args()
	
	# Check for conflicting arguments
	if args.api_key and args.list:
		print("Error: Cannot use both --api-key and --list together. Choose one.")
		sys.exit(1)
	
	# Batch mode: multiple keys from file
	if args.list:
		api_keys = parse_api_keys_from_file(args.list)
		print(f"[+] Loaded {len(api_keys)} API keys from {args.list}")
		scan_gmaps_batch(api_keys, args.proxy)
	# Single key mode
	elif args.api_key:
		scan_gmaps(args.api_key, args.proxy)
	# Interactive mode
	else:
		apikey = input("Please enter the Google API key you wanted to test: ")
		scan_gmaps(apikey, args.proxy)

if __name__ == "__main__":
    main()

