from bs4 import BeautifulSoup, Comment
import requests

#Credit for the detection code for several of the checks goes to Frederik Braun and his Mozilla intern project: Garmr
#See https://github.com/mozilla/Garmr
#All checks created here are licensed free and open source for anyone to use or modify

class HttpsCheck():
    test_name = "httpscheck"
    test_name_human = "HTTPS Check"
    severity = "moderate"
    description = "The HTTPS Check visits the HTTP version of your website to determine if visitors are redirected to an HTTPS version. If the site does not have an HTTPS version, the check will fail, but not deduct from the score, as websites that do not handle user information or logins may not need an HTTPS version."
    moreinfo = "HTTPS is a protocol that allows for secure communication between the client and server. HTTPS operates on top of SSL (Secure Socket Layer). It is useful for protecting against traffic sniffing and man-in-the-middle attacks because the data is encrypted before being sent over the network. Any site that utilizes user accounts, logins, or transfers sensitive information or payment details should always use HTTPS. For more information, see: http://en.wikipedia.org/wiki/HTTP_Secure."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, secure, scan_url):
        raw_data = ""
        try:
            if not secure:
                result = "skip"
                result_human = "You did not enter a URL beginning with HTTPS, so the HTTPS check did not attempt to check that the HTTP version redirects to the HTTPS version. To check your site's secure version, rerun this scan using HTTPS."
                raw_data = str(r.history)
            elif secure:
                self.total_points += 3
                scan_url_temp = scan_url.replace("https:", "http:")
                r_temp = requests.get(scan_url_temp)
                raw_data = str(r_temp.history)
                if (r_temp.url).startswith('https://'):
                    result = "pass"
                    result_human = "Visiting the HTTP version of your URL redirects to the HTTPS secure version. Note that not doing so is not always a security risk - sometimes a site has two distinct versions - HTTP and HTTPS."
                    self.points_collected += 3
                else:
                    result = "fail"
                    result_human = "Visiting the HTTP version of your URL does not redirect to the HTTPS secure version. Note that this is not always a security risk - sometimes a site has two distinct versions - HTTP and HTTPS."
            else:
                result = "unknown"
                result_human = "This test failed for some reason. The URL did not start with HTTP or HTTPS. Unknown protocol, perhaps."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist
    
class SecureCookieCheck():
    test_name = "securecookie"
    test_name_human = "Secure Cookie Flag Check"
    description = "If cookies are set, checks to ensure they are set with the secure flag."
    severity = "low"
    moreinfo = "The Secure cookie flag is used in combination with HTTPS and will only allow cookies to be transferred over a secure connection. If an attacker were to force a visitor to an HTTP version of your site, the cookies would not be accessible. Read more here: https://www.owasp.org/index.php/SecureFlag."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, secure):
        raw_data = ""
        try:
            if secure:
                if r.headers['Set-Cookie']:
                    self.total_points += 5
                    raw_data = str(r.headers['Set-Cookie'])
                    if "secure" in r.headers['Set-Cookie'].lower():
                        result = "pass"
                        result_human = "Cookies use the secure flag."
                        self.points_collected += 5
                    else:
                        result = "fail"
                        result_human = "Cookies are set but do not use the secure flag."
                else:
                    result = "skip"
                    result_human = "Cookies are not set. Nothing to check."
            else:
                result = "skip"
                result_human = "This site is using HTTP. The Secure flag operates in conjunction with HTTPS-enabled sites."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist
    
class StsHeaderCheck():
    test_name = "stscheck"
    test_name_human = "Strict Transport Security Check"
    description = "Checks for the presence of a Strict Transport Security (STS) header."
    severity = "low"
    moreinfo = "Strict Transport Security (sometimes called HTTP STS or HSTS) is a header that instructs browsers and devices that are interacting with the web page to only send data if it is using HTTPS. STS prevents SSL-stripping attacks by refusing to serve content over an HTTP connection. Read more here: http://en.wikipedia.org/wiki/HTTP_Strict_Transport_Security."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, secure):
        raw_data = ""
        try:
            if secure:
                self.total_points += 5
                if r.headers['Strict-Transport-Security']:
                    result = "pass"
                    result_human = "The STS header is set."
                    raw_data = str(r.headers['Strict-Transport-Security'])
                    self.points_collected += 5
                else:
                    result = "fail"
                    result_human = "The STS header is not set."
                    raw_data = str(r.headers)
            else:
                result = "skip"
                result_human = "This site is using HTTP. The STS header operates in conjunction with HTTPS-enabled sites."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist
    
class MixedContentCheck():
    test_name = "mixedcontent"
    test_name_human = "Mixed Content Check"
    description = "If HTTPS is used, checks to make sure all external resources are also loaded over HTTPS."
    severity = "moderate"
    moreinfo = "If a webpage uses HTTPS to secure user data, it is important that all the other resources (such as scripts, images, CSS, etc.) be loaded via HTTPS as well. If they are not, an attacker could leverage the insecure parts of the page to compromise the site's security. Google's JQuery and other APIs are provided over HTTPS if needed."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, secure, soup):
        raw_data = ""
        try:
            if secure:
                self.total_points += 7
                attrlist = ['codebase', 'background', 'src', 'usemap', 'data', 'icon', 'manifest', 'poster', 'archive']
                failtags = []
                tag_raw_data = []
                for tag in soup.findAll(True):
                    for attr in attrlist:
                        if tag.has_key(attr):
                            tag_raw_data.append(tag)
                            val = tag[attr]
                            if val.startswith('http:'):
                                failtags.append(tag)
                if len(failtags) == 0:
                    result = "pass"
                    result_human = "All resources are loaded via HTTPS."
                    self.points_collected += 7
                    raw_data = str(tag_raw_data)
                else:
                    result = "fail"
                    result_human = "There are resources on the page that are loaded via HTTP, creating a mixed content issue."
                    raw_data = str(failtags)
            else:
                result = "skip"
                result_human = "The site does not use HTTPS so mixed content is not an issue."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class XFrameOptionsCheck():
    test_name = "xframeoptions"
    test_name_human = "X-Frame-Options Check"
    description = "Checks for the presence of X-Frame-Options header and DENY or SAMEORIGIN as set."
    severity = "moderate"
    moreinfo = "X-Frame-Options is an option that can be set in the response headers that tells the browser how the site can be used within frames. Setting the option to DENY will prevent the page from being loaded within any frames, regardless of domain. Using SAMEORIGIN will allow the site to be framed on the same domain, but prevent other sites from framing it. This setting helps prevent against click-jacking attacks where an attacker will load one site in an iframe on a different domain, then place elements over the original login form, collecting user information as it is entered. To read more, see: https://developer.mozilla.org/en-US/docs/HTTP/X-Frame-Options."
    total_points = 0
    points_collected = 0
    
    def scan(self, r):
        try:        
            raw_data = ""
            self.total_points += 5
            if r.headers['X-Frame-Options']:
                if r.headers['X-Frame-Options'].lower() == 'deny':
                    result = "pass"
                    result_human = "X-Frame-Options header is set to DENY."
                    self.points_collected += 5
                elif r.headers['X-Frame-Options'].lower() == 'sameorigin':
                    result = "pass"
                    result_human = "X-Frame-Options header is set to SAMEORIGIN."
                    self.points_collected += 5
            else:
                result = "fail"
                result_human = "X-Frame-Options header is not set."
            raw_data = str(r.headers)
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class HttpOnlyCookieCheck():
    test_name = "httponlycookie"
    test_name_human = "HTTPOnly Cookie Flag Check"
    description = "If cookies are set, checks to ensure they are set as HTTPOnly."
    severity = "moderate"
    moreinfo = "The HTTPOnly flag can be added to cookies that are set. This flag will only allow the contents of the cookie to be accessed through the HTTP connection and not via client-side scripts. This helps if a site is exploited via cross-site scripting and a logged in user visits an exploited page. When the script runs, it will not have access to the session cookie, preventing the attacker from stealing the user's session. Read more here: https://www.owasp.org/index.php/HttpOnly."
    total_points = 0
    points_collected = 0
    
    def scan(self, r):
        raw_data = ""
        try:
            if r.headers['Set-Cookie']:
                self.total_points += 7
                if "httponly" in r.headers['Set-Cookie'].lower():
                    result = "pass"
                    result_human = "Cookies use the HTTPOnly flag."
                    self.points_collected += 7
                else:
                    result = "fail"
                    result_human = "Cookies are set but do not use the HTTPOnly flag."
            else:
                result = "skip"
                result_human = "Cookies are not set. Nothing to check."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class SecureFormCheck():
    test_name = "httpsform"
    test_name_human = "Secure Password Form Check"
    description = "If a form exists that asks for a password, checks to make sure the form submits data to an HTTPS page."
    severity = "high"
    moreinfo = "Any form that asks a user for a password should submit its data over HTTPS. Not doing so exposes the user to traffic sniffing as their password is transmitted in plain-text. This check checks the 'action' of a form."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, soup):
        raw_data = ""
        try:
            forms = soup.findAll('form')
            # look only at those form elements that have password type input elements as children
            forms = filter(lambda x: x.findChildren("input", type="password") ,forms)
            raw_data = str(forms)
            if len(forms) == 0:
                result = "skip"
                result_human = "There are no forms on this page containing password inputs."
            else:
                failforms = []
                self.total_points += 9
                for form in forms:
                    if secure:
                        if form['action'].startswith('http://'):
                            failforms.append(form)
                    else:
                        if not form['action'].startswith('https://'):
                            failforms.append(form)
                if len(failforms) == 0:
                    result = "pass"
                    result_human = "Forms containing password fields submit to HTTPS pages."
                    self.points_collected += 9
                else:
                    result = "fail"
                    result_human = "Forms containing password fields submit to HTTP insecure pages."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error. Possibly, the form did not have an 'action' attribute."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class CsrfFormCheck():
    test_name = "csrfcheck"
    test_name_human = "CSRF Check (Experimental)"
    description = "If there are forms on the page with POST methods, looks for CSRF tokens in hidden input fields or cookie values. (Experimental test)."
    severity = "moderate"
    moreinfo = "CSRF tokens should be used for all forms on a website to prevent submission of the form by a third-party. An attacker can trick a user into submitting the form by setting the action of a form on a malicious page to submit data to a form on your site."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, soup):
        raw_data = ""
        try:
            forms = soup.findAll('form')
            # look only at those form elements that have password type input elements as children
            forms = filter(lambda x: x.findChildren("input") ,forms)
            if len(forms) == 0:
                result = "skip"
                result_human = "There are no forms on this page."
            else:
                failforms = []
                self.total_points += 7
                #Loop through all forms that contain inputs
                for form in forms:
                    #Only search for forms that POST (many GET forms are used for searches and do not require CSRF tokens)
                    #if form['method'].lower() == "post":   #Doesn't work for some weird reason. Recognizes GET or POST but then errors out
                    if "post" in str(form.attrs).lower():
                        raw_data += str(form)
                        #Get a list of all the inputs that are children of the form
                        inputs = form.findChildren("input")
                        #All possible names for a CSRF token
                        csrf_names = ['csrf_token', 'csrf', 'csrf_val', 'csrftoken', 'csrfmiddlewaretoken', 'authenticity_token']
                        csrf_input = []
                        #Loop through all the child inputs
                        for input_item in inputs:
                            if input_item['name'] in csrf_names or 'csrf' in input_item['name'].lower():
                                csrf_input.append(input_item)
                        if len(csrf_input) == 0:
                            failforms.append(form)
                if len(failforms) == 0:
                    result = "pass"
                    result_human = "All forms either use GET or contain CSRF tokens if they POST."
                    self.points_collected += 7
                else:
                    result = "fail"
                    result_human = "One or more forms do not contain CSRF tokens and/or no session token could be found in cookies."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class CharEncodingCheck():
    test_name = "charencodingcheck"
    test_name_human = "Character Encoding Check"
    description = "Checks to ensure UTF-8 or equivalent encoding is specified."
    severity = "low"
    moreinfo = "Some XSS attacks have been executed by exploiting pages that do not specify their charset type (or use an older UTF version) by using UTF-8 characters to bypass output encoding."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, soup):
        raw_data = ""
        try:
            #FIND OUT HOW TO GET CHARSET
            meta = soup.findAll('meta')
            result = ""
            result_human = ""
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class CommentsCheck():
    test_name = "commentscheck"
    test_name_human = "HTML Comments Check (Experimental)"
    description = "Searches within HTML comments for sensitive words such as 'password' or 'admin' for potential accidental data exposure."
    severity = "low"
    moreinfo = "Sometimes developers will leave comments in their code that are meant to be removed later (such as 'the password for this page is x'). This test searches through the HTML comments for words such as these. Due to the nature of comments, this test may have a high rate of false positives."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, soup):
        raw_data = ""
        try:
            comments = soup.findAll(text=lambda text:isinstance(text, Comment))
            raw_data = str(comments)
            comment_keywords = ['password', 'username', 'admin', 'administrator', 'login info']
            failcomments = []
            for comment in comment_keywords:
                if comment in comments:
                    failcomments.append(comment)
                    result = "fail"
                    result_human += "The word '" + comment + "' was found in the HTML comments. "
            if len(failcomments) == 0:
                result = "pass"
                result_human = "No sensitive keywords were found in the comments. (Note: this is not comprehensive, please double-check.)"                    
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist

class CspCheck():
    test_name = "cspcheck"
    test_name_human = "X-Content-Security-Policy Check"
    description = "Checks for the presence of X-Content-Security-Policy header."
    severity = "low"
    moreinfo = "Content Security Policy is an optional header that establishes policies for the loading of content within a webpage. CSP was originally designed as a primary defense mechanism against XSS attacks. CSP works by specifying various rules for how content can be loaded, what domains the content can originate from, and whether inline scripts are allowed. This test does not grade this test due to the relatively new nature of CSP, but developers are encouraged to implement CSP headers. Read more: http://www.html5rocks.com/en/tutorials/security/content-security-policy/."
    total_points = 0
    points_collected = 0
    
    def scan(self, r):
        raw_data = ""
        try:
            if r.headers['X-Content-Security-Policy']:
                result = "pass"
                result_human = "CSP header is set."
                raw_data = str(r.headers['X-Content-Security-Policy'])
            else:
                result = "fail"
                result_human = "CSP header is not set."
                raw_data = str(r.headers)
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist
    
class InlineJsCheck():
    test_name = "inlinejscheck"
    test_name_human = "Inline JavaScript Check"
    description = "Checks for the presence of inline JavaScript for adherence to CSP."
    severity = "low"
    moreinfo = "Content Security Policy operates best when JavaScript is stored in external files and referenced via the script src tag (this is also a good coding practice). This test searches for the presence of inline JavaScript. Note that sometimes inline JavaScript is necessary for site functionality. This test is not part of the calculated grade."
    total_points = 0
    points_collected = 0
    
    def scan(self, r, soup):
        raw_data = ""
        try:
            scripts = soup.findAll('script')
            if len(scripts) == 0:
                result = "skip"
                result_human = "No script tags were found."
            inlinescripts = filter(lambda x: len(x.text) > 0, scripts)
            if len(inlinescripts) == 0:
                raw_data += (str(inlinescripts))[:100] + "...truncated..."
                result = "pass"
                result_human = "No inline JavaScript was found."
            else:
                raw_data += (str(inlinescripts))[:100] + "...truncated..."
                result = "fail"
                result_human = "Inline JavaScript was found."
        except:
            result = "unknown"
            result_human = "This test failed for some reason. Unknown error."
        returnlist = {"test_name":self.test_name, "test_name_human":self.test_name_human, "description":self.description, "severity":self.severity, "result":result, "result_human":result_human, "raw_data":raw_data, "moreinfo":self.moreinfo}
        return returnlist