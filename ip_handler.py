#!/usr/bin/python
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

"""
How is the verdict per IP computed?
Firstly result_per_tuple() function is called to count both all occurences and malicious occurences of each tuple in selected time window.
Return value of result_per_tuple() is tuple (number of malicous occurences, number of all occurences). Next step is counting a weighted score of the IP in selected timewindow.
Function get_weighted_score() is used. First step is to sum values over all  tuples  (get_result_per_tuple() is called for every  tuple). That leads to sum of tuple ratios.
Than percentage of malicous tuples is computed. Malicious tuple is a tuple which contains at leat one connection which was labeled as malicious.
Weighted score(WS) of IP is computed by multiplying sum of tuple ratios with percetage of malicious tuples. This value is stored in the tw_weigthed_scores list. After that, verdict can be computed.
For that sliding detection window (SDW) is used. If width of SDW is N, mean of last N weighted scores is compared to threshold.
If mean od N last WSs is equal or bigger than threshold, IP is labeled as 'Malicious'."""

from datetime import datetime
from time import gmtime, strftime
from colors import *
from utils import WhoisHandler
from utils import Classifier
from alerts import *
import time
import re
from math import *
import csv

#check if the log directory exists, if not, create it
logdir_path = "./logs"
if not os.path.exists(logdir_path):
    os.makedirs(logdir_path)
#file for logging
filename = logdir_path+"/" + 'log_' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')+'.txt'



""""

dataset = "CTU-Normal-6-filtered"
#malicious_list = set(line.rstrip('\n\r') for line in open("./Dataset/" + dataset +"/blacklist_" + dataset + ".txt")) #PREDELAAT"
malicious_list = []
print "******BLACKLIST******"
for item in malicious_list:
    print item
print "*********************"


"""
malicious_list = []

def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args):
        time1 = time.time()
        ret = f(*args)
        time2 = time.time()
        print '%s function took %0.3f ms' % (f.func_name, (time2-time1)*1000.0)
        return ret
    return wrap

class IpAddress(object):
    """IpAddress stores every detection and alerts """
    #TODO: storing ip as string? maybe there is a better way?
    def __init__(self, address, debug=False):
        self.address = address
        self.tuples = {}
        self.active_tuples = set()
        self.tuple_results = {}
        
        self.last_time = None
        self.last_verdict = None
        self.cumulative_log_likelihood = 0

        self.alerts = []
        self.debug = debug

    def add_detection(self, label, tuple, n_chars, input_time, dest_add, state):
        """ Stores new detection with timestamp"""
        # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
        detection = (label, n_chars, input_time, dest_add, state)
        self.last_time = input_time
        #first time we see this tuple
        if(not self.tuples.has_key(tuple)):
            self.tuples[tuple] = []
        #add detection to array
        self.tuples[tuple].append(detection)
        self.active_tuples.add(tuple)

    def get_alerts(self):
        """ Returns all the alerts stored in the IP object"""
        return self.alerts

    def close_time_window(self):
        """Removes all active tuples in this tw"""
        if self.debug:
            print "#Active tuples in ip:{} = {}".format(self.address,len(self.active_tuples))
        self.active_tuples.clear()
        self.tuple_results = {}

    def result_per_tuple(self, tuple, start_time, end_time,list):       
        """Compute ratio of malicious detection per tuple in timewindow determined by start_time & end_time"""
        try:
            # This counts the amount of times this tuple was detected by any model
            n_malicious = 0
            # This counts the amount of times this tuple was checked
            count = 0
            tuple_result = [];
            for detection in self.tuples[tuple]:
                #check if this detection belongs to the TimeWindow
                if (detection[2] >= start_time and detection[2] < end_time):
                    count += 1
                    if detection[0] != False:
                        n_malicious += 1
                    tuple_result.append(detection[0]);
            self.tuple_results[tuple] = ((n_malicious, count))
            return (n_malicious, count)
        except Exception as inst:
            print '\tProblem with result_per_tuple() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def last_positive(self, tuple, start_time, end_time):
        """Checks if last test of the tuple was positive"""
        result = False
        for detection in self.tuples[tuple]:
            #check if this detection belongs to the TimeWindow
            if (detection[2] >= start_time and detection[2] < end_time):
                if detection[0] != False:
                    result = True
                else:
                    result = False
        return result

    def get_feature_vector(self, start_time, end_time, malicious_list):
        #FORMAT: (#tuples, sum of tuple ratios, #ending with detection, % ending with detection, #at least once detected, % at least once detected,
        #flow detected, #flows checked, %flows detected, #fully detected tuples, %fully detected tuples, #clean tuples,% clean tuples, label)
        
        tuple_ratio_sum = 0
        tuple_counter = 0
        tuples_ending_positive = 0
        tuples_detected_at_least_once = 0
        clean_tuples = 0
        bad_tuples = 0
        total_detected = 0
        total_checked = 0

        connected_to_blacklisted = False
        for tuple4 in self.active_tuples:
            tuple_counter +=1
            (times_detected, times_checked) = self.result_per_tuple(tuple4,start_time,end_time,[])
            tuple_ratio_sum += (times_detected / float(times_checked))
            total_detected += times_detected
            total_checked += times_checked

            # tuple ended with positive detection
            if self.last_positive(tuple4,start_time,end_time):
                tuples_ending_positive+=1
            #tuples which were detected at least once
            if times_detected > 0:
                tuples_detected_at_least_once+=1

            #completaly clean tuples
            if times_detected == 0:
                clean_tuples+=1

            #completaly bad                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                     
            if times_detected == times_checked:
                bad_tuples+=1

            """
            dst_ip = tuple4.split('-')[1]
            if dst_ip in malicious_list: 
                connected_to_blacklisted = True
            #print tuple4.split('-')[1]
            """
        """
        if connected_to_blacklisted:
            label = "Malicious"
        else:
            label = "Normal"
        global COUNTER
        COUNTER = COUNTER + 1
        """
        #return (COUNTER,dataset,self.address,start_time,tuple_counter,tuple_ratio_sum, tuples_ending_positive, tuples_ending_positive/float(tuple_counter),
        # tuples_detected_at_least_once, tuples_detected_at_least_once/float(tuple_counter), total_detected, total_checked, total_detected/float(total_checked),
        # bad_tuples, bad_tuples/float(tuple_counter), clean_tuples, clean_tuples/float(tuple_counter),label)
        return (tuple_counter,tuple_ratio_sum, tuples_ending_positive, tuples_ending_positive/float(tuple_counter),
         tuples_detected_at_least_once, tuples_detected_at_least_once/float(tuple_counter), total_detected, total_checked, total_detected/float(total_checked),
         bad_tuples, bad_tuples/float(tuple_counter), clean_tuples, clean_tuples/float(tuple_counter))

    def store_feature_vector(self, vector, filename, whois_handler):    
        #print self.address + "\t" + str(vector)                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                             
        f = open(dataset+"_data.txt","a")
        #write all items of the vector
        for item in vector:
            f.write(str(item) + "\t")
        f.write("\n")
        for tuple4 in self.active_tuples:
            whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
            f.write("\t" + tuple4 + "["+  whois +"]\n" )

        with open(filename,'a') as csvfile:
            writer = csv.writer(csvfile,delimiter="\t",quotechar='|')
            writer.writerow(vector)

    def print_last_result(self, verbose, start_time, end_time, use_whois, whois_handler):
        """ 
        Print analysis of this IP in the last time window. Verbosity level modifies amount of information printed.
        """
        try:            
            # Print Malicious IPs
            if self.last_verdict.lower() == 'malicious' and verbose > 0:
                print red("\t+ {} verdict: {} (LogLikelihood sum: {})".format(self.address, self.last_verdict, self.cumulative_log_likelihood))                
                # Print those tuples that have at least 1 detection
                if verbose > 1 and verbose <= 3:
                    for tuple4 in self.active_tuples:
                        # Here we are checking for all the tuples of this IP in all the capture!! this is veryyy inefficient
                        tuple_result = self.tuple_results[tuple4]
                        # Is at least one tuple detected?
                        if tuple_result[0] != 0:
                            #Shall we use whois?
                            if use_whois:
                                whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
                                print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                            else:
                                print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])
                            if verbose > 2:
                                for detection in self.tuples[tuple4]:
                                    #check if detection fits in the TW
                                    if (detection[2] >= start_time and detection[2] < end_time):
                                        print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
                # Print those tuples that have at least 1 detection and also the ones that were not detected
                elif verbose > 3:
                    for tuple4 in self.active_tuples:
                        tuple_result = self.tuple_results[tuple4]
                        # Shall we use whois?
                        if use_whois:
                            whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
                            print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                        else:
                            print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])

                        #print detections
                        for detection in self.tuples[tuple4]:
                            #check if detection fits in the TW
                            if (detection[2] >= start_time and detection[2] < end_time):
                                print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
            # Print normal IPs
            elif verbose > 3:
                print green("\t+ {} verdict: {} (LogLikelihood sum: {})".format(self.address, self.last_verdict, self.cumulative_log_likelihood))
                if verbose > 4:
                    for tuple4 in self.active_tuples:
                        tuple_result = self.tuple_results[tuple4]
                        # Is at least one tuple checked?
                        if tuple_result[1] != 0:
                            #Shall we use whois?
                            if use_whois:
                                whois = whois_handler.get_whois_data(self.tuples[tuple4][0][3])
                                print "\t\t{} [{}] ({}/{})".format(tuple4,whois,tuple_result[0],tuple_result[1])
                            else:
                                print "\t\t{} ({}/{})".format(tuple4,tuple_result[0],tuple_result[1])
                            if verbose > 5:
                                for detection in self.tuples[tuple4]:
                                    #check if detection fits in the TW
                                    if (detection[2] >= start_time and detection[2] < end_time):
                                        print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
        except Exception as inst:
            print '\tProblem with print_last_result() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def add_result(self, result, threshold):
        """"Stores classification result (log likelihood) and assignes label based on cumulative log likelihood"""
        self.last_risk = 0
        self.cumulative_log_likelihood += result
        if self.cumulative_log_likelihood > threshold:
            self.alerts.append(IpDetectionAlert(datetime.now(),self.address,self.cumulative_log_likelihood))
            self.last_verdict = "Malicious"
        else:
            self.last_verdict = "Normal"
        
class IpHandler(object):
    """Class which handles all IP actions for slips. Stores every IP object in the session, provides summary, statistics etc."""
    def __init__(self, verbose, debug, whois, classifier):
        self.addresses = {}
        self.active_addresses = list()
        self.verbose = verbose
        self.debug = debug
        self.whois = whois
        self.classifier = Classifier(classifier)
        self.whois_handler = WhoisHandler("WhoisData.txt")
        
                
    def process_timewindow(self, start_time, end_time, threshold):
        #get feature vector from all active IPs
        vectors = []
        for ip in self.active_addresses:
            #Get the IpAddress object
            address = self.addresses[ip]
            vectors.append(address.get_feature_vector(start_time,end_time,[]))
        #classify each IP
        results = self.classifier.get_log_likelihood(vectors)

        #process classification
        for i in range(0,len(self.active_addresses)):
            address = self.addresses[self.active_addresses[i]]
            #store the result
            address.add_result(results[i], threshold)
            #print the result
            address.print_last_result(self.verbose, start_time, end_time, self.whois, self.whois_handler)
            #close TW in the address
            address.close_time_window()
        
        #close TW
        self.active_addresses = []

    def get_ip(self, ip_string):
        """Get the IpAddress object with id 'ip_string'. If it doesn't exists, create it"""
        #Have I seen this IP before?
        try:
            ip = self.addresses[ip_string]
        # No, create it
        except KeyError:
            ip = IpAddress(ip_string,self.debug)
            self.addresses[ip_string] = ip
        #register ip as active in this TW
        if ip_string not in self.active_addresses:
            self.active_addresses.append(ip_string)
        return ip

    def get_alerts(self):
        ret = set()
        for ip in self.addresses.values():
            if len(ip.alerts) > 0:
                for alert in ip.get_alerts():
                    ret.add(alert)
        return ret

    def print_alerts(self):
        """ Gater all the alerts in the handler and print them"""
        detected_counter = 0
        self.whois_handler.store_whois_data_in_file()
        print '\nFinal Alerts generated:'
        f = open(filename,"w")
        f.write("DATE:\t{}\nSummary of adresses in this capture:\n\n".format(datetime.now().strftime('%Y/%m/%d %H:%M:%S')))
        f.write('Alerts:\n')
        for ip in self.addresses.values():
            if len(ip.alerts) > 0:
                detected_counter+=1
                print "\t - "+ ip.address
                f.write( '\t - ' + ip.address + '\n')
                for alert in ip.get_alerts():
                    print "\t\t" + str(alert)
                    f.write( '\t\t' + str(alert) + '\n')

        s = "{} IP(s) out of {} detected as malicious.".format(detected_counter,len(self.addresses.keys()))
        f.write(s)
        print s
        f.close()




