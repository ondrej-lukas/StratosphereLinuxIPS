#!/usr/bin/python
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

import re
import sys
import pickle
from math import log
from xgboost import XGBClassifier
import time
import os
import numpy

class WhoisHandler(object):
    """This class is used for getting the whois information. Since queries to whois service takes too much time it stores all the information localy in the txt file.
     Structure of the file:
     [ip address][TAB][Description][\n]"""

    def __init__(self,whois_file):
        self.whois_data = {}
        self.filename = whois_file
        self.new_item = False
        try:
            with open(whois_file) as f:
                for line in f:
                    s = re.split("\t",line.strip())
                    if len(s) > 1:
                        self.whois_data[s[0]] = s[1]
            print "Whois file '{}' loaded successfully".format(whois_file)            
        except IOError:
            print "Whois informaton file:'{}' doesn't exist!".format(self.filename)
            pass
    
    def get_whois_data(self,ip):
        #do we have it in the cache?
        try:
            import ipwhois
        except ImportError:
            print 'The ipwhois library is not install. pip install ipwhois'
            return False
        # is the ip in the cache
        try:
            desc = ""
            desc = self.whois_data[ip]
            return desc
        except KeyError:
            # Is not, so just ask for it
            try:
                obj = ipwhois.IPWhois(ip)
                data = obj.lookup_whois()
                try:
                    desc = data['nets'][0]['description'].strip().replace('\n',' ') + ',' + data['nets'][0]['country']
                except AttributeError:
                    # There is no description field
                    desc = ""
                except TypeError:
                    #There is a None somewhere, just continue..
                    desc = ""
            except ValueError:
                # Not a real IP, maybe a MAC
                desc = 'Not an IP'
                pass
            except IndexError:
                # Some problem with the whois info. Continue
                pass        
            except ipwhois.IPDefinedError as e:
                if 'Multicast' in e:
                    desc = 'Multicast'
                desc = 'Private Use'
            except ipwhois.WhoisLookupError:
                print 'Error looking the whois of {}'.format(ip)
                # continue with the work\
                pass
            except ipwhois.exceptions.HTTPLookupError:
                print 'Error looking the whois of {}'.format(ip)
                # continue with the work\
                pass
            # Store in the cache
            self.whois_data[ip] = desc
            self.new_item = True;
            return desc
        except Exception as inst:
            print '\tProblem with get_whois_data() in utils.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)


    def store_whois_data_in_file(self):
        """Writes whois information in the file"""
        if self.new_item:
            f = open(self.filename,"w")
            for item in self.whois_data.items():
                f.write('{}\t{}\n'.format(item[0],item[1]));
            f.close();
        else:
            print "No changes in the whois file."

class Classifier(object):
    """This class contains classifier from scikit-learn library"""

    def __init__(self, filename):
        self.model = None
        try:
            self.model = pickle.load(open(filename, "rb"))
        except IOError:
            print "ERROR: Loading serialzied RandomForestClassifier from '{}' was NOT successful.".format(filename)
            exit(1)

    """Return list of logarithms of likelihood ratio"""
    def get_log_likelihood(self, vector_list):
        likelihoods = []
        #get probabilities
        results = self.model.predict_proba(vector_list)
        #compute log likelihood
        for result in results:
            if result[0] == 0:
                #likelihoods.append(log(sys.float_info.min))
                likelihoods.append(log(0.000001))
            elif result[1] == 0:
                likelihoods.append(log(1000000))
            else:
                likelihoods.append( log((result[0]/result[1]))) # possible zero division?
        return likelihoods

    def classify(self,features):
        return self.model.predict(numpy.array(features))






