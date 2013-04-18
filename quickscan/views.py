from django.shortcuts import render, redirect
from django.http import Http404
from django.utils.timezone import utc
from datetime import datetime
from urlparse import urlparse
from quickscan.models import quickScan
import requests, uuid, json

#List of sites that will not be allowed to scan
FORBIDDEN_SITES = [
    'facebook.com',
    'twitter.com',
]

#Can GET or POST the /quickscan page
def home(request):
    if request.method == 'GET':
        return render(request, 'quickscan/quickscan_new.html')
    elif request.method == 'POST' and request.POST:
        #Get URL user entered
        try:
            url_entered = request.POST["url_entered"]
        except:
            data = {"error":"Could not read URL input. Please enter a valid URL."}
            return render(request, 'quickscan/quickscan_new.html', data)
        if len(url_entered) < 5:
            data = {"error":"You must enter a valid URL."}
            return render(request, 'quickscan/quickscan_new.html', data)
        
        #Check for http:// or https://, if not, add it
        if not url_entered.startswith('https://'):
            if not url_entered.startswith('http://'):
                url_entered = "http://" + url_entered
        
        #Make sure not scanning a forbidden site
        hostname = urlparse(url_entered).hostname
        if hostname in FORBIDDEN_SITES or ".gov" in url_entered or ".mil" in url_entered:
            data = {"error":"This site is blacklisted from scanning."}
            return render(request, 'quickscan/quickscan_new.html', data)
        
        #Ensure the site is valid and up
        if not check_connection(url_entered):
            data = {"error":"The URL entered is not responding. Please ensure the site is up."}
            return render(request, 'quickscan/quickscan_new.html', data)
        
        #We've gotten to here, no errors so far, valid URL
        scan_id = str(uuid.uuid4())
        
        #Add to database
        scan = quickScan(scan_uuid=scan_id, scan_date=datetime.utcnow().replace(tzinfo=utc), scan_url=url_entered, scan_status='running')
        scan.save()
        
        #Now, redirect them to the scan results page
        return redirect('/quickscan/' + scan_id)
    else:
        raise Http404

#Results page - look up the scan in db, provide info
def results(request, scan_uuid):
    data = {}
    scan = quickScan.objects.get(scan_uuid=scan_uuid)
    #Convert json from string to python dict
    if len(scan.scan_results) > 1:
        scan_results_dict = json.loads(scan.scan_results)
        data = {"scan_uuid":scan.scan_uuid, "scan_date":scan.scan_date, "scan_url":scan.scan_url, "scan_status":scan.scan_status, "scan_grade": scan_results_dict[scan_uuid]['grade'], "scan_results_https":scan_results_dict[scan_uuid]['HTTPS Checks'], "scan_results_cookie":scan_results_dict[scan_uuid]['Cookie Security'], "scan_results_form":scan_results_dict[scan_uuid]['Form Security'], "scan_results_header":scan_results_dict[scan_uuid]['Additional Header Checks'], "scan_results_csp":scan_results_dict[scan_uuid]['Content Security Policy'], "scan_results_other":scan_results_dict[scan_uuid]['Other Security Checks']}
    else:
        scan_results_dict = scan.scan_results
        data = {"scan_uuid":scan.scan_uuid, "scan_date":scan.scan_date, "scan_url":scan.scan_url, "scan_status":scan.scan_status, "scan_results":scan_results_dict}    

    return render(request, 'quickscan/quickscan_results.html', data)

#Extra functions
def check_connection(url):
    try:
        #Only need to get the headers to ensure the site is up
        r = requests.head(url)
        return True
    except:
        return False