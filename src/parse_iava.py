#!/usr/bin/env python
# -*- coding: iso-8859-15 -*-
# Copyright (C) 2014  David Sirrine (dsirrine@gmail.com)

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

# File Name : reporter.py
# Creation Date : December 17, 2013
# Created By : David Sirrine
# Last Modified : Wed Jan  8 16:02:03 EST 2014
# Purpose : Provide objects parse iava information out of disa provided xml

import xml.etree.ElementTree as xet
import reporter
import urllib
import parse_cve


class ParseIava(object):
    '''
    classdocs
    '''
    def __init__(self):
        self._iava_parse()

    def _iava_parse(self):
        print "Opening test.xml and parsing"
        urlarg = 0
        if urlarg == 0:
            doc = xet.parse("test.xml")
        else:
            url = "http://iase.disa.mil/stigs/downloads/xml/iavm-to-cve(u).xml"
            doc = urllib.urlopen(url)
        
        iava = doc.getroot()
        for iavaEntry in iava.findall("IAVM"):
            self.iavaTitle = self._iava_title(iavaEntry)
            self.iavaNumber = self._iava_num(iavaEntry)
            self.iavaRelease = self._iava_rel(iavaEntry)
            self.iavaSeverity = self._iava_sev(iavaEntry)
            self.iavaRevisionDate = self._iava_rev_date(iavaEntry)
            self.iavaRevisionNum = self._iava_rev_num(iavaEntry)
            self.iavaCVENumbers = self._iava_cve_num(iavaEntry)
            self.iavaRefName = self._iava_cve_ref_name(iavaEntry)
            self.iavaRefURL = self._iava_cve_ref_url(iavaEntry)
            print "\tInformation parsed for IAVA " + self.iavaNumber
            print "\tWriting IAVA information for " + self.iavaNumber + "to " + self.iavaNumber + ".doc"
            self._print_out(self.iavaTitle,
                            self.iavaNumber,
                            self.iavaRelease,
                            self.iavaSeverity,
                            self.iavaRevisionDate,
                            self.iavaRevisionNum,
                            self.iavaCVENumbers,
                            self.iavaRefName,
                            self.iavaRefURL)
        
    def _iava_title(self, iavaEntry):
        iavaTitle = iavaEntry[0].attrib.get("Title")
        return iavaTitle
    def _iava_num(self, iavaEntry):
        iavaNumber = iavaEntry[0].attrib.get("IAVM")
        return iavaNumber
    def _iava_rel(self, iavaEntry):
        iavaRelease = iavaEntry[0].attrib.get("ReleaseDate")
        return iavaRelease
    def _iava_sev(self, iavaEntry):
        iavaSeverity = iavaEntry[0].attrib.get("Severity")
        return iavaSeverity
    def _iava_rev_date(self, iavaEntry):
        iavaRevisionDate = iavaEntry[1].attrib.get("Date")
        return iavaRevisionDate
    def _iava_rev_num(self, iavaEntry):
        iavaRevisionNum = iavaEntry[1].attrib.get("Number")
        return iavaRevisionNum
    def _iava_cve_num(self, iavaEntry):
        iavaCVENumbers = [ ]
        for iavaCVEList in iavaEntry[2].findall('CVENumber'):
            iavaCVENumbers.append(iavaCVEList.text)
        return iavaCVENumbers
    def _iava_cve_ref_name(self, iavaEntry):
        iavaRefName = []
        for iavaRefList in iavaEntry[3].findall('Reference'):
            iavaRefName.append(iavaRefList.attrib.get("RefName"))
        return iavaRefName
    def _iava_cve_ref_url(self, iavaEntry):
        iavaRefURL = []
        for iavaRefList in iavaEntry[3].findall('Reference'):
            iavaRefURL.append(iavaRefList.attrib.get("URL"))
        return iavaRefURL

    def _print_out(self,
                   iavaTitle,
                   iavaNumber,
                   iavaRelease,
                   iavaSeverity,
                   iavaRevisionDate,
                   iavaRevisionNum,
                   iavaCVENumbers,
                   iavaRefName,
                   iavaRefURL):
        iavaOut = self.iavaNumber + '.doc'
        try:
            open(iavaOut)
        except:
            f = open(iavaOut, 'wb+')
        else:
            f = open(iavaOut, 'a+')
        p = reporter.IavaReporter()
        p._print_iava_title(iavaTitle, f)
        p._print_iava_num(iavaNumber, f)
        p._print_iava_release(iavaRelease, f)
        p._print_iava_sev(iavaSeverity, f)
        p._print_iava_rev_date(iavaRevisionDate, f)
        p._print_iava_rev_num(iavaRevisionNum, f)
        p._print_iava_ref(iavaRefName, iavaRefURL, f)
        p._print_iava_cve_list_with_url(iavaCVENumbers, f)
        f.close()
        i = 0
        while i < len(self.iavaCVENumbers):
            parse_cve.CveParse(self.iavaCVENumbers[i])
            i += 1

x = ParseIava()
