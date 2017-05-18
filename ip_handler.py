#!/usr/bin/python
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

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


from sklearn.metrics import confusion_matrix
import itertools
import numpy as np
#import matplotlib.pyplot as plt

#check if the log directory exists, if not, create it
logdir_path = "./logs"
if not os.path.exists(logdir_path):
    os.makedirs(logdir_path)
#file for logging
filename = logdir_path+"/" + 'log_' + datetime.now().strftime('%Y-%m-%d %H:%M:%S')+'.txt'
DATASETNAME ="CTU-Malware-Capture-Botnet-44_only_infected"

class_names = ["Malicious","Normal"]
INFECTED = ["147.32.84.165"]

"""
def plot_confusion_matrix(cm, classes,
                          normalize=False,
                          title='Confusion matrix',
                          cmap=plt.cm.Oranges):
    plt.imshow(cm, interpolation='nearest', cmap=cmap)
    plt.title(title)
    plt.colorbar()
    tick_marks = np.arange(len(classes))
    plt.xticks(tick_marks, classes, rotation=45)
    plt.yticks(tick_marks, classes)

    if normalize:
        cm = cm.astype('float') / cm.sum(axis=1)[:, np.newaxis]
        print("Normalized confusion matrix")
    else:
        print('Confusion matrix, without normalization')

    print(cm)
    thresh = cm.max() / 2.
    for i, j in itertools.product(range(cm.shape[0]), range(cm.shape[1])):
        plt.text(j, i, cm[i, j],
                 horizontalalignment="center",
                 color="white" if cm[i, j] > thresh else "black")

    plt.tight_layout()
    plt.ylabel('True label')
    plt.xlabel('Predicted label')
"""

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
        self.connections = {}
        self.active_connections = set()
        self.connection_results = {}
        self.sdw = []
        
        self.last_time = None
        self.last_verdict = None
        self.last_vector = None

        self.alerts = []
        self.debug = debug

    def add_detection(self, label, connection, n_chars, input_time, dest_add, state):
        """ Stores new detection with timestamp"""
        # The detection structure is a 3-tuple of a label, the number of chars when it was detected and when it was detected
        detection = (label, n_chars, input_time, dest_add, state)
        self.last_time = input_time
        #first time we see this tuple
        if(not self.connections.has_key(connection)):
            self.connections[connection] = []
        #add detection to array
        self.connections[connection].append(detection)
        self.active_connections.add(connection)

    def get_alerts(self):
        """ Returns all the alerts stored in the IP object"""
        return self.alerts

    def close_time_window(self):
        """Removes all active tuples in this tw"""
        if self.debug:
            print "#Active connections in ip:{} = {}".format(self.address,len(self.active_connections))
        self.active_connections.clear()
        self.tuple_results = {}

    def result_per_connection(self, connection, start_time, end_time):       
        """Compute connection ratio"""
        try:
            # This counts the amount of times this tuple was detected by any model
            detected_states = 0
            # This counts the amount of times this tuple was checked
            states_counter = 0
            for detection in self.connections[connection]:
                #check if this detection belongs to the TimeWindow
                if (detection[2] >= start_time and detection[2] < end_time):
                    states_counter +=1
                    if detection[0] != False:
                        detected_states += 1
            self.connection_results[connection] = (detected_states,states_counter)
            return (detected_states, states_counter)
        except Exception as inst:
            print '\tProblem with result_per_connection() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def get_tw_vector(self, start_time, end_time):     

        connections = 0
        conection_ratio_sum = 0
        clean_connections = 0
        suspicious_connections = 0
        bad_connections = 0
        states = 0
        detected_states = 0

        for conn in self.active_connections:
            connections +=1
            #get result from the connection
            (times_detected, times_checked) = self.result_per_connection(conn,start_time,end_time)
            
            conection_ratio_sum += (times_detected / float(times_checked))
            detected_states += times_detected
            states  += times_checked


            #clean tuple
            if times_detected == 0:
                clean_connections +=1
            #suspicious connections (detected at least once)
            if times_detected > 0:
                suspicious_connections +=1

            #bad connections                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                   
            if times_detected == times_checked:
                bad_connections+=1
        return (connections, clean_connections, suspicious_connections, bad_connections, clean_connections/float(connections),suspicious_connections/float(connections),
         bad_connections/float(connections), states, detected_states,detected_states/float(states),conection_ratio_sum, conection_ratio_sum/float(connections))

    def get_sdw_vector(self):
        """DESCRIPTION"""
        #first TW
        if len(self.sdw) == 0:
            return (0,0,0,0,0,0,0)
        else:
            connections = 0
            clean_connections = 0
            suspicious_connections = 0
            bad_connections = 0
            for item in self.sdw:
                connections += item[0]
                clean_connections += item[1]
                suspicious_connections += item[2]
                bad_connections += item[3]
            return (connections, clean_connections, suspicious_connections, bad_connections, clean_connections/float(connections), suspicious_connections/float(connections), bad_connections/float(connections))

    def get_features(self, start_time,end_time,sdw_size, training=False):
        """DESCRIPTION"""
        #get vectors
        current_tw_vector = self.get_tw_vector(start_time,end_time)
        sdw_vector = self.get_sdw_vector()
        #put current tw vector in the sdw
        self.sdw.append(current_tw_vector)
        #move the sdw
        if len(self.sdw) > sdw_size:
            self.sdw = self.sdw[1:]
        if training:
            global COUNTER
            self.store_feature_vector((COUNTER,DATASETNAME,self.address,str(start_time)) + current_tw_vector + sdw_vector + (LABEL,),DATASETNAME+"_datamatrix_tw_sdw.csv")
            COUNTER +=1
        self.last_vector = current_tw_vector
        return self.last_vector

    def store_feature_vector(self, vector, filename): 
        print "line:{}".format(vector[0])                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                                              
        with open(filename,'a') as csvfile:
            writer = csv.writer(csvfile,delimiter=",",quotechar='|')
            writer.writerow(vector)

    def print_last_result(self, verbose, start_time, end_time, use_whois, whois_handler):
        """ 
        Print analysis of this IP in the last time window. Verbosity level modifies amount of information printed.
        """
        try:            
            # Print Malicious IPs
            if self.last_verdict.lower() == 'malicious' and verbose > 0:
                print red("\t+ {} verdict: {}".format(self.address, self.last_verdict))             
                # Print those tuples that have at least 1 detection
                if verbose > 2:
                    for conn in self.active_connections:
                        # Here we are checking for all the tuples of this IP in all the capture!! this is veryyy inefficient
                        conn_result = self.connection_results[conn]
                        #Shall we use whois?
                        if use_whois:
                            whois = whois_handler.get_whois_data(self.connections[conn][0][3])
                            print "\t\t{} [{}] ({}/{})".format(conn,whois,conn_result[0],conn_result[1])
                        else:
                            print "\t\t{} ({}/{})".format(conn,conn_result[0],conn_result[1])
                        if verbose > 3:
                            for detection in self.connections[conn]:
                                #check if detection fits in the TW
                                if (detection[2] >= start_time and detection[2] < end_time):
                                    print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
            # Print normal IPs
            elif verbose > 3:
                print green("\t+ {} verdict: {}".format(self.address, self.last_verdict))
                if verbose > 4:
                    for conn in self.active_connections:
                        conn_result = self.connection_results[conn]
                        #Shall we use whois?
                        if use_whois:
                            whois = whois_handler.get_whois_data(self.connections[conn][0][3])
                            print "\t\t{} [{}] ({}/{})".format(conn,whois,conn_result[0],conn_result[1])
                        else:
                            print "\t\t{} ({}/{})".format(conn,conn_result[0],conn_result[1])
                        if verbose > 5:
                            for detection in self.connections[conn]:
                                #check if detection fits in the TW
                                if (detection[2] >= start_time and detection[2] < end_time):
                                    print("\t\t\tDstIP: {}, Label:{:>40} , Detection Time:{}, State(100 max): {}").format(detection[3], detection[0], detection[2], detection[4][:100])
        except Exception as inst:
            print '\tProblem with print_last_result() in ip_handler.py'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

        
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
        self.SDW_size = 12

        self.test_labels = []
        self.real_labels = []
        
                
    def process_timewindow(self, start_time, end_time):
        #get feature vector from all active IPs
        vectors = []
        for ip in self.active_addresses:
            #Get the IpAddress object
            address = self.addresses[ip]
            vectors.append(address.get_features(start_time,end_time, self.SDW_size))
        #classify each IP
        results = self.classifier.classify(vectors)
        #process classification
        for i in range(0,len(self.active_addresses)):
            address = self.addresses[self.active_addresses[i]]
            #store verdict in the object
            address.last_verdict = results[i]
            if results[i].lower() == 'malicious':
                address.alerts.append(IpDetectionAlert(datetime.now(), address, vectors[i]))
            #print the result
            address.print_last_result(self.verbose, start_time, end_time, self.whois, self.whois_handler)
            if address.address in INFECTED:
                self.real_labels.append("Malicious")
            else:
                self.real_labels.append("Normal")
            self.test_labels.append(results[i])
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
        TP = 0
        FN = 0
        FP = 0
        TN = 0
        self.whois_handler.store_whois_data_in_file()
        print '\nFinal Alerts generated:'
        f = open(filename,"w")
        f.write("DATE:\t{}\nSummary of adresses in this capture:\n\n".format(datetime.now().strftime('%Y/%m/%d %H:%M:%S')))
        f.write('Alerts:\n')
        for ip in self.addresses.values():
            if len(ip.alerts) > 0:

                if ip.address in INFECTED:
                    TP += 1
                else:
                    FP +=1

                detected_counter+=1
                print "\t - "+ ip.address
                f.write( '\t - ' + ip.address + '\n')
                for alert in ip.get_alerts():
                    print "\t\t" + str(alert)
                    f.write( '\t\t' + str(alert) + '\n')
            else:
                if ip.address in INFECTED:
                    FN += 1
                else:
                    TN +=1


        s = "{} IP(s) out of {} detected as malicious.".format(detected_counter,len(self.addresses.keys()))
        f.write(s)
        print s
        f.close()


        cnf_matrix = confusion_matrix(self.real_labels, self.test_labels)        
        print "NEW VERSION per tw:"
        print cnf_matrix
        print "NEW VERSION at the end:"
        print [[TP,FN],[FP,TN]]

        """
        np.set_printoptions(precision=2)
        plt.figure()
        plot_confusion_matrix(cnf_matrix, classes=class_names, title='Confusion matrix, without normalization')
        plt.savefig('./experiments/CM_'+ DATASETNAME+'_SDW'+'.png',dpi=400, bbox_inches='tight')
        plt.figure()
        plot_confusion_matrix(cnf_matrix, classes=class_names, normalize=True, title='Normalized confusion matrix')
        plt.savefig('./experiments/CM_'+ DATASETNAME+'_normalized'+'_SDW'+'.png',dpi=400, bbox_inches='tight')
        """





