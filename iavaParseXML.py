#!/usr/bin/python
# -*- coding: iso-8859-15 -*-
# Copyright (C) 2013  David Sirrine (dsirrine@gmail.com)

# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.

# File Name : iavaParseXML.py
# Creation Date : 12-06-2013
# Created By : David Sirrine
# Last Modified : Sat 14 December 2013 16:49:11 PM EST
# Purpose :

import xml.etree.ElementTree as xet
import sys, argparse
from BeautifulSoup import BeautifulSoup as bs

def __main__ ():


#    print ("Please select an operation you would like to perform:")
#    print ("\n")
#    print ("\t [1] Perform operations based on IAVA")
#    print ("\t [2] Perform operations based on CVE")
#    print ("\n")
#    op = raw_input("Enter your selection: ")
#    if op == 1:
#        _iava_menu()
#    elif op == 2:
#        _cve_menu()
#    else:
#        "You did not select a valid entry. Please try again."
#        __main__()

    _iava_parse()
            
def _iava_menu():
    
    print ("Please select an operation you would like to perform:")
    print ("\n")
    print ("\t [1] Parse IAVA database based on date or date range")
    print ("\t [2] Search IAVA database based on IAVA number")
    print ("\n")
    op = raw_input("Enter your selection: ")
    
    if op == 1:
        _iava_date_menu()
    elif op == 2:
        _iava_num_search()
    else:
        "You did not select a valid entry. Please try again."
        _iava_menu()
        
def _cve_menu():
    ''' For CVE operations '''
    print ("this is a test.")
    sys.exit(0)
    
def _iava_date_menu():
    '''for searching iava database based on date'''
    
    print ("Please select an operation you would like to perform:")
    print ("\n")
    print ("\t [1] Parse by date range")
    print ("\t [2] Parse by specific date")
    print ("\n")
    op = raw_input("Enter your selection: ")
    
    if op == 1:
        _iava_daterange_search()
    elif op == 2:
        _iava_date_search()
    else:
        "You did not select a valid entry. Please try again."
        _iava_date_menu()

def _iava_daterange_search():
    ''' For CVE operations '''
    print ("this is a test.")
    sys.exit(0)
        
def _iava_date_search():
    ''' For CVE operations '''
    print ("this is a test.")
    sys.exit(0)
            
def _iava_num_search():
    '''for searching iava database based on iava number'''
    
def _iava_parse():
    url = "http://iase.disa.mil/stigs/downloads/xml/iavm-to-cve(u).xml"
    doc = xet.parse("test.xml")
    # doc = et.parse("iavm-to-cve.20131207.xml")
    iava = doc.getroot()
    for iavaEntry in iava.findall("IAVM"):
        iavaTitle = iavaEntry[0].attrib.get("Title")
        iavaNumber = iavaEntry[0].attrib.get("IAVM")
        iavaRelease = iavaEntry[0].attrib.get("ReleaseDate")
        iavaSeverity = iavaEntry[0].attrib.get("Severity")
        iavaRevisionDate = iavaEntry[1].attrib.get("Date")
        iavaRevisionNum = iavaEntry[1].attrib.get("Number")
        iavaCVENumbers = [ ]
        for iavaCVEList in iavaEntry[2].findall('CVENumber'):
            iavaCVENumbers.append(iavaCVEList.text)
        iavaRefName = []
        iavaRefURL = []
        for iavaRefList in iavaEntry[3].findall('Reference'):
            iavaRefName.append(iavaRefList.attrib.get("RefName"))
            iavaRefURL.append(iavaRefList.attrib.get("URL"))
    _iava_console_out(iavaNumber, iavaTitle, iavaRelease, iavaSeverity, iavaRevisionDate, iavaRevisionNum, iavaCVENumbers, iavaRefName, iavaRefURL)

def _iava_console_out(iavaNumber, iavaTitle, iavaRelease, iavaSeverity, iavaRevisionDate, iavaRevisionNum, iavaCVENumbers, iavaRefName, iavaRefURL):
    print ("IAVA:\t\t" + iavaNumber)
    print ("Title:\t\t" + iavaTitle)
    print ("Release Date:\t" + iavaRelease)
    print ("Rev Date:\t" + iavaRevisionDate)
    print ("Rev Number:\t" + iavaRevisionNum)
    print ("Severity:\t" + iavaSeverity)
    print ("CVE List:\t")
    i = 0
    while i < len(iavaCVENumbers):
        cve = iavaCVENumbers[i]
        _cve_html_parse(iavaCVENumbers, cve)
        print ("\n")
        i += 1
    i = 0
    while i < len(iavaRefName):
        print ("Reference %s: " % i + iavaRefName[i] + " - " + "\t %s" % iavaRefURL[i])
        i += 1

def _cve_html_parse(iavaCVENumbers, cve):
    
    cveURL = "https://access.redhat.com/security/cve/%s" % cve
    cveFile = open("CVE-2013-5844.html")
    doc = cveFile.read()
    data = bs(''.join(doc))
    
    _parse_cve_table(data.findAll("table")[0], cveURL)
    _parse_cvss_table(data.findAll("table")[1])
    _parse_rhsa_table(data.findAll("table")[2])
    
def _parse_cve_table(table, cveURL):
    '''This function is to parse the cve table from Red Hat CVE database (https://access.redhat.com/security/cve/)'''
    cveImpact = _parse_cve_impact(table.findAll('tr')[0])
    cvePubDate = _parse_cve_pubdate(table.findAll('tr')[1])
    cveBZInfo = _parse_cve_bugzilla(table.findAll('tr')[2])
    cveIAVARef = _parse_cve_iavaref(table.findAll('tr')[3])
    print ("\tCVE URL: %s" % cveURL)
    print ("\t\tImpact: \t\t\t%s" % cveImpact)
    print ("\t\tDate Public: \t\t\t%s" % cvePubDate)
    print ("\t\tBugzilla#: \t\t\t%s" % cveBZInfo[0])
    print ("\t\tBugzilla URL: \t\t\t%s" % cveBZInfo[1])
    print ("\t\tIAVA Number: \t\t\t%s" % cveIAVARef)
    print ("\n")
    
def _parse_cve_impact(impact): 
    cveImpact = impact.findNext('td').text
    return cveImpact

def _parse_cve_pubdate(date): 
    cvePubDate = date.findNext('td').text
    return cvePubDate

def _parse_cve_bugzilla(bz): 
    cveBZInfo = []
    cveBZNum = bz.findNext('td').a.text
    cveBZInfo.append(cveBZNum)
    url = bz.find('a', href=True)
    cveBZURL = url['href']
    cveBZInfo.append(cveBZURL)
    return cveBZInfo

def _parse_cve_iavaref(iavaref): 
    cveIAVARef = iavaref.findNext('td').text
    return cveIAVARef
    
def _parse_cvss_table(table):
    '''This function is to parse the cvss table from Red Hat CVE database (https://access.redhat.com/security/cve/)'''
    cvssBaseScore = _parse_cvss_base_score(table.findAll('tr')[0])
    cvssBaseMetrics = _parse_cvss_base_metrics(table.findAll('tr')[1])
    cvssAccessVector = _parse_cvss_access_vector(table.findAll('tr')[2])
    cvssAccessComplexity = _parse_cvss_access_complexity(table.findAll('tr')[3])
    cvssAuthentication = _parse_cvss_authentication(table.findAll('tr')[4])
    cvssConfidentialityImpact = _parse_cvss_confidentiality_impact(table.findAll('tr')[5])
    cvssIntegrityImpact = _parse_cvss_integrity_impact(table.findAll('tr')[6])
    cvssAvailabilityImpact = _parse_cvss_availability_impact(table.findAll('tr')[7])
    print ("\tCVSS Information From Red Hat CVE Database")
    print ("\t\tBase Score: \t\t\t%s" % cvssBaseScore)
    print ("\t\tBase Metrics: \t\t\t%s" % cvssBaseMetrics)
    print ("\t\tAccess Vector: \t\t\t%s" % cvssAccessVector)
    print ("\t\tAccess Complexity: \t\t%s" % cvssAccessComplexity)
    print ("\t\tAuthentication: \t\t%s" % cvssAuthentication)
    print ("\t\tConfidentiality Impact: \t%s" % cvssConfidentialityImpact)    
    print ("\t\tIntegrity Impact: \t\t%s" % cvssIntegrityImpact)
    print ("\t\tAvailability Impact: \t\t%s" % cvssAvailabilityImpact)
    print ("\n")
    
def _parse_cvss_base_score(bs):
    cvssBaseScore = bs.findNext('td').text
    return cvssBaseScore

def _parse_cvss_base_metrics(bm):
    cvssBaseMetrics = bm.findNext('td').text
    return cvssBaseMetrics

def _parse_cvss_access_vector(av):
    cvssAccessVector = av.findNext('td').text
    return cvssAccessVector

def _parse_cvss_access_complexity(ac):
    cvssAccessComplexity = ac.findNext('td').text
    return cvssAccessComplexity

def _parse_cvss_authentication(auth):
    cvssAuthentication = auth.findNext('td').text
    return cvssAuthentication

def _parse_cvss_confidentiality_impact(ci):
    cvssConfidentialityImpact = ci.findNext('td').text
    return cvssConfidentialityImpact

def _parse_cvss_integrity_impact(ii):
    cvssIntegrityImpact = ii.findNext('td').text
    return cvssIntegrityImpact

def _parse_cvss_availability_impact(ai):
    cvssAvailabilityImpact = ai.findNext('td').text
    return cvssAvailabilityImpact
        
def _parse_rhsa_table(table):
    '''This function is to parse the rhsa table from Red Hat CVE database (https://access.redhat.com/security/cve/)'''
    

    rhsaPlatform = []
    rhsaNum = []
    rhsaURL = []
    rhsaRelease = []
    
    entries = table.findAll('tr')
    i = 1
    while i < len(entries):
        rhsaPlatform.append(_parse_rhsa_platform(entries[i]))
        rhsaNum.append(_parse_rhsa_num(entries[i]))
        rhsaURL.append(_parse_rhsa_url(entries[i]))
        rhsaRelease.append(_parse_rhsa_release(entries[i]))        
        i += 1
    count = 0
    print ("\tRHSAs Release Information")
    while len(rhsaPlatform) > count: 
        print ("\t\tRHSA Number: \t\t%s" % rhsaNum[count])
        print ("\t\tRHSA URL: \t\t%s" % rhsaURL[count])
        print ("\t\tPlatform Affected: \t%s" % rhsaPlatform[count])
        print ("\t\tRelease Date: \t\t%s" % rhsaRelease[count])
        print ("\n")
        count += 1
    sys.exit(0)


def _parse_rhsa_platform(rhsa):
    
    platform = rhsa.findAll('td')[0].text
    return platform
    
def _parse_rhsa_num(rhsa):
    rhsanum = rhsa.findAll('td')[1].a.text
    return (rhsanum)

def _parse_rhsa_url(rhsa):
    rhsaurl = (rhsa.find('a', href=True)['href'])
    return (rhsaurl)

def _parse_rhsa_release(rhsa):
    release = rhsa.findAll('td')[2].text
    return (release)
   
def iavaxmlout():
    "This function provides formatting to output iava to cve analysis to XML"
    # TODO(dsirrine@redhat.com): Create stub 
    print ("Functionality coming soon! Please run with -t only")
    sys.exit(2)
        
if __name__ == "__main__":
    __main__()
