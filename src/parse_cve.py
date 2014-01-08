'''
Created on Dec 17, 2013

@author: dsirrine
'''

import reporter
import urllib
from BeautifulSoup import BeautifulSoup as bs


class CveParse:
    '''
    classdocs
    '''
        
    def __init__(self, iavaCVENumbers):
        self.cve = iavaCVENumbers
        self._cve_html_parse(self.cve)


    def _cve_html_parse(self, cve):
        self.cveURL = "https://access.redhat.com/security/cve/%s" % cve
        print "Opening CVE URL " + self.cveURL
        cveFile = urllib.urlopen(self.cveURL)
        self.data = bs(''.join(cveFile))
        
        self._parse_cve_table(self.data.findAll("table")[0])
        self._parse_cvss_table(self.data.findAll("table")[1])
        self._parse_rhsa_table(self.data.findAll("table")[2])
               
    
    def _parse_cve_table(self, table):
        '''This function is to parse the cve table from Red Hat CVE database (https://access.redhat.com/security/cve/)'''
        print "\tParsing CVE table information for CVE " + self.cve
        self.cveImpact = self._parse_cve_impact(table.findAll('tr')[0])
        self.cvePubDate = self._parse_cve_pubdate(table.findAll('tr')[1])
        self.cveBZInfo = self._parse_cve_bugzilla(table.findAll('tr')[2])
        self.cveIAVARef = self._parse_cve_iavaref(table.findAll('tr')[3])
        self._print_cve(self.cveImpact,
                        self.cvePubDate,
                        self.cveBZInfo,
                        self.cveIAVARef,
                        self.cveURL)
        
    def _parse_cve_impact(self, impact): 
        cveImpact = impact.findNext('td').text
        return cveImpact
    
    def _parse_cve_pubdate(self, date): 
        cvePubDate = date.findNext('td').text
        return cvePubDate
    
    def _parse_cve_bugzilla(self, bz): 
        cveBZInfo = []
        cveBZNum = bz.findNext('td').a.text
        cveBZInfo.append(cveBZNum)
        url = bz.find('a', href=True)
        cveBZURL = url['href']
        cveBZInfo.append(cveBZURL)
        return cveBZInfo
    
    def _parse_cve_iavaref(self, iavaref): 
        self.cveIAVARef = iavaref.findNext('td').text
        return self.cveIAVARef
        
    def _parse_cvss_table(self, table):
        '''This function is to parse the cvss table from Red Hat CVE database (https://access.redhat.com/security/cve/)'''
        self.cvssBaseScore = self._parse_cvss_base_score(table.findAll('tr')[0])
        self.cvssBaseMetrics = self._parse_cvss_base_metrics(table.findAll('tr')[1])
        self.cvssAccessVector = self._parse_cvss_access_vector(table.findAll('tr')[2])
        self.cvssAccessComplexity = self._parse_cvss_access_complexity(table.findAll('tr')[3])
        self.cvssAuthentication = self._parse_cvss_authentication(table.findAll('tr')[4])
        self.cvssConfidentialityImpact = self._parse_cvss_confidentiality_impact(table.findAll('tr')[5])
        self.cvssIntegrityImpact = self._parse_cvss_integrity_impact(table.findAll('tr')[6])
        self.cvssAvailabilityImpact = self._parse_cvss_availability_impact(table.findAll('tr')[7])
        self._print_cvss()

        
    def _parse_cvss_base_score(self, bs):
        BaseScore = bs.findNext('td').text
        return BaseScore
    
    def _parse_cvss_base_metrics(self, bm):
        self.cvssBaseMetrics = bm.findNext('td').text
        return self.cvssBaseMetrics
    
    def _parse_cvss_access_vector(self, av):
        self.cvssAccessVector = av.findNext('td').text
        return self.cvssAccessVector
    
    def _parse_cvss_access_complexity(self, ac):
        self.cvssAccessComplexity = ac.find('td').text
        return self.cvssAccessComplexity
    
    def _parse_cvss_authentication(self, auth):
        self.cvssAuthentication = auth.find('td').text
        return self.cvssAuthentication
    
    def _parse_cvss_confidentiality_impact(self, ci):
        self.cvssConfidentialityImpact = ci.find('td').text
        return self.cvssConfidentialityImpact
    
    def _parse_cvss_integrity_impact(self, ii):
        self.cvssIntegrityImpact = ii.find('td').text
        return self.cvssIntegrityImpact
    
    def _parse_cvss_availability_impact(self, ai):
        self.cvssAvailabilityImpact = ai.find('td').text
        return self.cvssAvailabilityImpact
            
    def _parse_rhsa_table(self, table):
        '''This function is to parse the rhsa table from Red Hat CVE database (https://access.redhat.com/security/cve/)'''
        
    
        self.rhsaPlatform = []
        self.rhsaNum = []
        self.rhsaURL = []
        self.rhsaRelease = []
        # entries is a list type. Iterating through entries returns beautifulsoup tag type
        entries = table.findAll('tr')
        
        i = 1
        while i < len(entries):
            # entries[i] variable returns beautifulsoup tag type with the first table row with non-header data. 
            self.rhsaPlatform.append(self._parse_rhsa_platform(entries[i]))
            self.rhsaNum.append(self._parse_rhsa_num(entries[i]))
            self.rhsaURL.append(self._parse_rhsa_url(entries[i]))
            self.rhsaRelease.append(self._parse_rhsa_release(entries[i]))        
            i += 1
            self._print_rhsa()
    
    def _parse_rhsa_platform(self, rhsa):
        
        platform = rhsa.findAll('td')[0].text
        return platform
        
    def _parse_rhsa_num(self, rhsa):
        num = rhsa.findAll('td')[1].a.text
        return num
    
    def _parse_rhsa_url(self, rhsa):
        url = (rhsa.find('a', href=True)['href'])
        return url
    
    def _parse_rhsa_release(self, rhsa):
        release = rhsa.findAll('td')[2].text
        return release
        
    def _print_cve(self,
                   cveImpact,
                    cvePubDate,
                    cveBZInfo,
                    cveIAVARef,
                    cveURL):
        
        iavaOut = self.cveIAVARef + '.doc'
        try:
            open(iavaOut)
        except:
            f = open(iavaOut, 'wb+')
        else:
            f = open(iavaOut, 'a+')

        p = reporter.CveReporter()
        f.writelines("-------------------------------" + self.cve + "-------------------------------\n")
        f.writelines("Information for " + self.cve + ":\n")
        p._print_cve_url(cveURL, f)
        p._print_cve_impact(cveImpact, f)
        p._print_cve_pub_date(cvePubDate, f)
        p._print_cve_bz_num(cveBZInfo, f)
        p._print_cve_bz_url(cveBZInfo, f)
        p._print_cve_iava_num(cveIAVARef, f)
        f.close()

    def _print_cvss(self):
        iavaOut = self.cveIAVARef + '.doc'
        try:
            open(iavaOut)
        except:
            f = open(iavaOut, 'wb+')
        else:
            f = open(iavaOut, 'a+')
           
        p = reporter.CveReporter()
        f.writelines("\nCVSS Information for " + self.cve + ":\n")
        
        p._print_cve_cvss_bs(self.cvssBaseScore, f)

        p._print_cve_cvss_bm(self.cvssBaseMetrics, f)

        p._print_cve_cvss_av(self.cvssAccessVector, f)

        p._print_cve_cvss_ac(self.cvssAccessComplexity, f)

        p._print_cve_cvss_auth(self.cvssAuthentication, f)

        p._print_cve_cvss_ci(self.cvssConfidentialityImpact, f)

        p._print_cve_cvss_ii(self.cvssIntegrityImpact, f)

        p._print_cve_cvss_ai(self.cvssAvailabilityImpact, f)
        
        f.close()
        
    def _print_rhsa(self):
        iavaOut = self.cveIAVARef + '.doc'
        try:
            open(iavaOut)
        except:
            f = open(iavaOut, 'wb+')
        else:
            f = open(iavaOut, 'a+')
            
        p = reporter.CveReporter()
        f.writelines("\nRHSA Information for " + self.cve + ":\n")
        if len(self.rhsaNum) == 0:
            f.writelines("No RHSA information available for this CVE")
        else:
            p._print_cve_rhsa_num(self.rhsaNum, f)
            p._print_cve_rhsa_url(self.rhsaURL, f)
            p._print_cve_rhsa_Platform(self.rhsaPlatform, f)
            p._print_cve_rhsa_Release(self.rhsaRelease, f)
            f.close()
