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
You should now be able to run the django server:

    $ python manage.py runserver 127.0.0.1:8000

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
            #The following variables must be set somewhere
            points_collected = 0
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

# Frequently Asked Questions

Note: These Q/As apply to the hosted version of this project.

### What is this service?

This is a security scanning service. Using passive scanning techniques, it will check a website to ensure compliance with a number of common and recommended security standards.

### How much does it cost?

Nothing! It's 100% free to use this service. The goal is to improve security across the internet and make security checks easily accessible to developers who may not be knowledgeable about all the security protocols they should be using.

### Will this break my website?

No. Although security scanners have a reputation for throwing thousands of requests per minute at a website (and sometimes DOSing it in the process), this tool makes only two (three for HTTPS) requests to your site. It will not submit any forms or data, nor will it download files or otherwise harm your site in any way. Think of it as two people loading your web page.

### What kinds of things are checked?

This scanner will check your response headers and page body for a number of common web security standards. For example, it will check for the presence of X-Frame-Options, the HttpOnly and Secure flags for cookies, the use of HTTPS, etc. It does not current support checking for other known vulnerabilities such as cross-site scripting or SQL injection (that would require more intense scans).

### Does my site really need everything recommended here?

It depends. This site is aiming for an absolute best security approach. If you are scanning a blog or a simple static site, you probably don't need HTTPS or X-Frame-Options might be overkill. This scan works best for slightly more complex web apps that may have login forms, transfer sensitive user information, or otherwise require more security. This doesn't mean you can't scan simple sites; it just means the results will be much less helpful.

### Why don't I need to validate my site? Can't anyone use this to scan any website?

Yes, anyone can scan any website (with a few exceptions). However, unlike other scanners this is not actively checking for vulnerabilities but instead passively looking at the response that everyone receives. In other words, anyone can see the data this tool sees simply by visiting the web page. There is no 'hacking' or attacking occurring.

### Is this legal?

I'm not a lawyer, so this is answer is offered "as is." However, this scan does nothing more than perform a GET request of the URL in question and analyze the headers and content for various security best practices. There is no modification of content, cookies, URL parameters, or any other kind of injection or repeated requesting. If you are a site owner and still do not feel comfortable allowing others to send this request, you may add your site to the blacklist via the email in the footer. This being said, you ARE legally responsible for any action you take using these results. So if it tells you that site X doesn't use STS and you perform a man-in-the-middle attack, you're legally responsible.

### If it's legal then why can't I scan sites ending in .gov?

Because discussing the answer to the previous question with federal agents in my apartment is not something I have planned for this week.

### How is the grade determined?

The grade is a percentage calculated based on the number of tests successfully performed (not those skipped or that returned an error) and the result of each test. Each test is given a severity ranking based on how large of a security concern and how exploitable the vulnerability is (I assigned these; they are based on my research and may not represent real world conditions for every website). Based on this ranking, a numerical value between 0 and 10 is given to the test for 'possible points.' Then, based on the results, either some or all of those points will be added to the score for later calculation of a percentage.

### How can I improve my grade?

Within each test result, there is a tab for 'More Information.' For many of the tests, it includes information about implementing the security practice or includes links that provide further instruction. By adding the security check and re-running the scan, your grade should improve if the scan was successful and the check implemented correctly.

### Can I share my results?

Yes! Every scan is given a unique id that is also part of the URL. Simply copy the URL and share it. Because results contain a lot of information (and I don't have infinite storage for the site's database) results may be deleted after 30 days.

### Why did a check give me the wrong response? I know I have ___ implemented but it returned 'fail'.

Because this is a learning project I finished up in a weekend and there are probably errors. I did my best to implement the checks, but there will undoubtedly be something that it misses or reads incorrectly. If you find a glaring error, feel free to shoot me an email at matthewdf10 (at) gmail (dot) com.

### But this site scored less than 100%! Why can you not get a 100?

Yes, I've scanned the site with itself. As I mentioned, not every security check is necessary for every website. The score reflects adherence to a long list of security policies, many of which may be excessive for a very simple site. It is ultimately up to the developer to implement the necessary precautions; this site simply helps point out if something might be missing.

### So who are you and what are your credentials?

I'm a student studying computer networking and security. I've done a lot of research, reading, and project development on my own time related to web application security. I've also had multiple internships working in network and application security, including a six month co-op at Mozilla where I worked primarily with web application security where I worked on a larger scale version of something similar to this. I am certainly not an expert! I made this project as a learning experience for me, as well as to help improve security around the web. I enjoy hacking on personal projects, setting up services in VMs and breaking them, and responsibly reporting web security bugs. My email is matthewdf10 (at) gmail (dot) com if you have additional questions.

### Why is this hosted on a .tk domain? Isn't that kind of shady?

Dot TK domains are free. I'm not making any money from this service so I don't plan to spend extra money on it.