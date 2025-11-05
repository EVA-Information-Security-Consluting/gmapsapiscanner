import requests
import warnings 
import json
import sys
import os
import argparse


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
	response = requests.get(url, verify=False, allow_redirects=False)
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','Authorization':'key='+apikey})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','X-Goog-FieldMask':'routes.duration,routes.distanceMeters'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','X-Goog-FieldMask':'originIndex,destinationIndex,duration,distanceMeters'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','X-Goog-FieldMask':'places.displayName,places.id'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json','X-Goog-FieldMask':'places.displayName,places.formattedAddress'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json'})
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
	response = requests.post(url, data=postdata, verify=False, headers={'Content-Type':'application/json'})
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
	response = requests.get(url, verify=False, allow_redirects=False)
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

	print("-------------------------------------------------------------")
	print("  Results 			|| Cost Table/Reference to Exploit:")
	print("-------------------------------------------------------------")
	for i in range (len(vulnerable_apis)):
	    print("- " + vulnerable_apis[i])
	print("-------------------------------------------------------------")
	print("Reference for up-to-date pricing:")
	print("https://cloud.google.com/maps-platform/pricing")
	print("https://developers.google.com/maps/billing/gmp-billing")
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

def main() -> None:
	warnings.filterwarnings("ignore")
	
	parser = argparse.ArgumentParser(
		description='EVA Upgraded - Google Maps API Scanner by Bar Hajby',
		formatter_class=argparse.RawDescriptionHelpFormatter,
		epilog='''
Examples:
  python eva_gmaps_scanner.py --api-key YOUR_KEY
  python eva_gmaps_scanner.py -a YOUR_KEY -p http://127.0.0.1:8080
  python eva_gmaps_scanner.py -a YOUR_KEY --proxy http://proxy.example.com:3128
		'''
	)
	
	parser.add_argument(
		'-a', '--api-key',
		type=str,
		help='Google Maps API key to test'
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
	
	# Get API key from argument or prompt
	if args.api_key:
		apikey = args.api_key
	else:
		apikey = input("Please enter the Google Maps API key you wanted to test: ")
	
	# Run scan with optional proxy
	scan_gmaps(apikey, args.proxy)

if __name__ == "__main__":
    main()

