Web-Security-GUI
================

A Django website that scans provided URLs for common security practices

# About This Project
This is a quick project I wrote to bring web security testing to developers and users quickly by removing typical
barriers such as verifying site ownership, account creation, etc. In two clicks, you can scan a site for common
vulnerabilities and receive a grade. It passively scans websites using two or three GET requests, so there is no
parameter manipulation or any other "hacking" attacks on the site.

#  Installation
First, clone the repo to a folder on your local disk.

    $ git clone https://github.com/matthewdfuller/Web-Security-GUI.git
    
Next, copy the settings-distrib.py file to settings.py

    $ cd secgui
    $ cp secgui/settings-distrib.py secgui/settings.py
    
Within this file, edit the local path, database information, and other parameters as necessary to reflect your local installation.

    $ vim secgui/settings.py

If you are not developing, change the debug setting to False within settings.py.

```python
    DEBUG = False
```

# Writing Checks
The file 'secgui/scanner/scantests.py' contains the classes for the various checks performed on the response headers, cookies, and code.
To write your own check, create a new class with the following format:

```python
    class checkName():
    test_name = "singlewordcheckname"
    test_name_human = "A Human Readable Test Name"
    severity = "info/low/moderate/high"
    description = "A semi-short description of what this check does."
    moreinfo = "More information about the security vulnerability the check is testing for."
    total_points = 0    #0-10; 0=no value, 10=high severity
    points_collected = 0    #Leave as 0 for now.
    
    def scan(self, r, secure, scan_url, soup):    #'secure' is a boolean value for HTTPS enabled (True) or not (False)    'scan_url' is the URL of the scan   'soup' is a BeautifulSoup object
        raw_data = ""   #Leave blank
        try:
            #Perform tests below. Some examples are here
            if secure:
                #do something
            if r.headers['Set-Cookie']:
                    self.total_points += 5
                    raw_data = str(r.headers['Set-Cookie'])
            result = "pass/fail/skip"
            result_human = "A human readable description of what the result means."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist
```

Next, in the 'secgui/scanner/views.py' file, add the following:

```python
    #Create scan objects
    yourcheck = checkName()
    
    jsonobj[scan_uuid]["XXXX"].append(httpscheck.scan(r, secure, scan_url, soup))
    #XXXX can be: "HTTPS Checks", "Additional Header Checks", "Cookie Security", "Form Security", or "Other Security Checks" depending on which category it best fits.
    
    #Add your check to the list:
    all_checks = [httpscheck, securecookiecheck, ..., yourcheck, ...]
```

That's it!