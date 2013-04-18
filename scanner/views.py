from django.http import HttpResponse
from django.views.decorators.http import require_http_methods
from django.core.serializers.json import DjangoJSONEncoder
from bs4 import BeautifulSoup, Comment
from quickscan.models import quickScan
import sys, requests, json
from scantests import HttpsCheck, SecureCookieCheck, StsHeaderCheck, MixedContentCheck, XFrameOptionsCheck, HttpOnlyCookieCheck, SecureFormCheck, CsrfFormCheck, CommentsCheck, CspCheck, InlineJsCheck, CharEncodingCheck

@require_http_methods(["POST"])
def scan(request):
    scan_uuid = request.POST['scan_uuid']
    try:
        scan = quickScan.objects.get(scan_uuid=scan_uuid)
    except:
        message = {'success': False, 'error': 'invalid-scan-id'}
        return HttpResponse(json.dumps(message), mimetype="application/json")
    
    #Successful lookup of scan_uuid, now begin the scanning!
    scan_url = scan.scan_url
    
    #Create the first json obj
    jsonobj_begin = {scan_uuid: {
        "HTTPS Checks": [],
        "Cookie Security": [],
        "Form Security": [],
        "Additional Header Checks": [],
        "Content Security Policy": [],
        "Other Security Checks": []
        }
    }
    
    return_json = runscans(scan_url, jsonobj_begin, scan_uuid)
    
    #Update the database
    scan.scan_status = 'done'
    scan.scan_results = json.dumps(return_json, cls=DjangoJSONEncoder)
    scan.save()
    
    message = {'success': True}
    #Return the response to the user
    return HttpResponse(json.dumps(message), mimetype="application/json")
    
    
#SCANNER FUNCTIONS

#The main function that coordinates the scan
def runscans(scan_url, jsonobj, scan_uuid):
    total_points = 0
    points_collected = 0
    secure = False
    
    #Retrieve the response from the page
    if scan_url.startswith('https://'):
        secure = True
    r = requests.get(scan_url)
    soup = BeautifulSoup(r.text, 'html.parser') #Solves hanging issue on mod_wsgi. See: http://stackoverflow.com/questions/12618567/problems-running-beautifulsoup4-within-apache-mod-python-django
    
    #Create scan objects
    httpscheck = HttpsCheck()
    securecookiecheck = SecureCookieCheck()
    stsheadercheck = StsHeaderCheck()
    mixedcontentcheck = MixedContentCheck()
    xframeoptionscheck = XFrameOptionsCheck()
    httponlycookiecheck = HttpOnlyCookieCheck()
    secureformcheck = SecureFormCheck()
    csrfformcheck = CsrfFormCheck()
    commentscheck = CommentsCheck()
    #charencodingcheck = CharEncodingCheck()
    cspcheck = CspCheck()
    inlinejscheck = InlineJsCheck()
    
    #Run checks
    jsonobj[scan_uuid]["HTTPS Checks"].append(httpscheck.scan(r, secure, scan_url))
    jsonobj[scan_uuid]["HTTPS Checks"].append(securecookiecheck.scan(r, secure))
    jsonobj[scan_uuid]["HTTPS Checks"].append(stsheadercheck.scan(r, secure))
    jsonobj[scan_uuid]["HTTPS Checks"].append(mixedcontentcheck.scan(r, secure, soup))
    
    jsonobj[scan_uuid]["Additional Header Checks"].append(xframeoptionscheck.scan(r))
    
    jsonobj[scan_uuid]["Cookie Security"].append(httponlycookiecheck.scan(r))
    
    jsonobj[scan_uuid]["Form Security"].append(secureformcheck.scan(r, soup))
    jsonobj[scan_uuid]["Form Security"].append(csrfformcheck.scan(r, soup))
    
    jsonobj[scan_uuid]["Other Security Checks"].append(commentscheck.scan(r, soup))
    #jsonobj[scan_uuid]["Other Security Checks"].append(charencodingcheck.scan(r, soup))
    
    jsonobj[scan_uuid]["Content Security Policy"].append(cspcheck.scan(r))
    jsonobj[scan_uuid]["Content Security Policy"].append(inlinejscheck.scan(r, soup))

    #all_checks = [httpscheck, securecookiecheck, stsheadercheck, mixedcontentcheck, xframeoptionscheck, httponlycookiecheck, secureformcheck, csrfformcheck, commentscheck, charencodingcheck, cspcheck, inlinejscheck]
    all_checks = [httpscheck, securecookiecheck, stsheadercheck, mixedcontentcheck, xframeoptionscheck, httponlycookiecheck, secureformcheck, csrfformcheck, commentscheck, cspcheck, inlinejscheck]
    
    #Calc the grade
    jsonobj[scan_uuid]["grade"] = grade(all_checks)
    return jsonobj

def grade(all_checks):
    total_points = 0
    points_collected = 0
    
    for check in all_checks:
        total_points += check.total_points
        points_collected += check.points_collected
    
    return str(int(((float(points_collected))/(float(total_points)))*100)) + "%"