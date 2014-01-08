'''
Created on Dec 17, 2013

@author: dsirrine
'''

class IavaReporter():
    '''Print out IAVA information from iava xml from DISA'''
    def _print_iava_num(self, iavaNumber, f):
        '''Print IAVA number to file'''
        print "\t\t" + iavaNumber
        f.writelines("IAVA:\t\t\t" + iavaNumber + "\n")
    def _print_iava_title(self, iavaTitle, f):
        ''' '''
        print "\t\t" + iavaTitle
        f.writelines("Title:\t\t\t" + iavaTitle + "\n")       
    def _print_iava_release(self, iavaRelease, f):
        ''' '''
        print "\t\t" + iavaRelease
        f.writelines("Release Date:\t\t" + iavaRelease + "\n")
    def _print_iava_rev_date(self, iavaRevisionDate, f):
        ''' '''
        print "\t\t" + iavaRevisionDate
        f.writelines("Rev Date:\t\t" + iavaRevisionDate + "\n")
    def _print_iava_rev_num(self, iavaRevisionNum, f):
        ''' '''
        print "\t\t" + iavaRevisionNum
        f.writelines("Rev Number:\t\t" + iavaRevisionNum + "\n\n")
    def _print_iava_sev(self, iavaSeverity, f):
        ''' '''
        print "\t\t" + iavaSeverity
        f.writelines("Severity:\t\t" + iavaSeverity + "\n")
    def _print_iava_cve_list_nums(self, iavaCVENumbers, f):
        ''' '''
        f.writelines("CVE List:\n\n")
        i = 0
        while i < len(iavaCVENumbers):
#            cve = iavaCVENumbers[i]
#            _cve_html_parse(iavaCVENumbers, cve, f)
            print "\t\t\t" + iavaCVENumbers[i] + "\n"
            f.writelines(iavaCVENumbers[i])
            f.writelines("\n")
            i += 1
    def _print_iava_cve_list_with_url(self, iavaCVENumbers, f):
        ''' '''
        i = 0
        f.writelines("List of CVE's associated with this IAVA:\n")
        while i < len(iavaCVENumbers):
            print "\t\thttps://access.redhat.com/security/cve/" + iavaCVENumbers[i]
            f.writelines("https://access.redhat.com/security/cve/" + iavaCVENumbers[i])
            if (i + 1 == len(iavaCVENumbers)):
                f.writelines("\n\n")
            else:
                f.writelines("\n")
            i += 1
            
    def _print_iava_ref(self, iavaRefName, iavaRefURL, f):
        f.writelines("References associated with this IAVA:\n")
        i = 0
        while i < len(iavaRefName):
            print "\t\t" + iavaRefName[i] + " - " + iavaRefURL[i]
            f.writelines(iavaRefName[i] + " - " + iavaRefURL[i])
            if (i + 1 == len(iavaRefName)):
                f.writelines("\n\n")
            else:
                f.writelines("\n")
            i += 1
            
class CveReporter:
    def _print_cve_url(self, cveURL, f):
        print "\tCVE URL:\t\t" + cveURL
        f.writelines("URL:\t\t\t%s" % cveURL + "\n")
    
    def _print_cve_impact(self, cveImpact, f):
        print "\tImpact:\t\t" + cveImpact
        f.writelines("Impact:\t\t\t%s" % cveImpact + "\n")
        
    def _print_cve_pub_date(self, cvePubDate, f):
        print "\tDate:\t\t" + cvePubDate
        f.writelines("Date Public:\t\t%s" % cvePubDate + "\n")
        
    def _print_cve_bz_num(self, cveBZInfo, f):
        print "\tBZ Number:\t\t" + cveBZInfo[0]
        f.writelines("Bugzilla#:\t\t%s" % cveBZInfo[0] + "\n")
        
    def _print_cve_bz_url(self, cveBZInfo, f):
        print "\tBZ URL:\t\t" + cveBZInfo[1]
        f.writelines("Bugzilla URL:\t\t%s" % cveBZInfo[1] + "\n")
        
    def _print_cve_iava_num(self, cveIAVARef, f):
        print "\tCVE Iava Ref:\t\t" + cveIAVARef
        f.writelines("IAVA Number:\t\t%s" % cveIAVARef + "\n")

    def _print_cve_cvss_bs(self, cvssBaseScore, f):
        f.writelines("Base Score:\t\t\t%s" % cvssBaseScore + "\n")

    def _print_cve_cvss_bm(self, cvssBaseMetrics, f):
        f.writelines("Base Metrics:\t\t\t%s" % cvssBaseMetrics + "\n")
    
    def _print_cve_cvss_av(self, cvssAccessVector, f):
        f.writelines("Access Vector:\t\t\t%s" % cvssAccessVector + "\n")

    def _print_cve_cvss_ac(self, cvssAccessComplexity, f):
        f.writelines("Access Complexity:\t\t%s" % cvssAccessComplexity + "\n")
    
    def _print_cve_cvss_auth(self, cvssAuthentication, f):
        f.writelines("Authentication:\t\t\t%s" % cvssAuthentication + "\n")
    
    def _print_cve_cvss_ci(self, cvssConfidentialityImpact, f):
        f.writelines("Confidentiality Impact:\t\t%s" % cvssConfidentialityImpact + "\n")
    
    def _print_cve_cvss_ii(self, cvssIntegrityImpact, f):
        f.writelines("Integrity Impact:\t\t%s" % cvssIntegrityImpact + "\n")
    
    def _print_cve_cvss_ai(self, cvssAvailabilityImpact, f):
        f.writelines("Availability Impact:\t\t%s" % cvssAvailabilityImpact + "\n")
    
    def _print_cve_rhsa_num(self, rhsaNum, f):
        i = 0
        while len(rhsaNum) > i: 
            f.writelines("RHSA Number:\t\t%s" % rhsaNum[i] + "\n")
            i += 1
  
    def _print_cve_rhsa_url(self, rhsaURL, f):
        i = 0
        while len(rhsaURL) > i: 
            f.writelines("RHSA URL:\t\t%s" % rhsaURL[i] + "\n")
            i += 1
             
    def _print_cve_rhsa_Platform(self, rhsaPlatform, f):
        i = 0
        while len(rhsaPlatform) > i: 
            f.writelines("RHSA Platform:\t\t%s" % rhsaPlatform[i] + "\n")
            i += 1
             
    def _print_cve_rhsa_Release(self, rhsaRelease, f):
        i = 0
        while len(rhsaRelease) > i: 
            f.writelines("RHSA Release:\t\t%s" % rhsaRelease[i] + "\n")
            i += 1
