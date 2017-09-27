#!/usr/bin/python -u
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
# Author: Sebastian Garcia. eldraco@gmail.com , sebastian.garcia@agents.fel.cvut.cz

import sys
import signal
from colors import *
from datetime import datetime
from datetime import timedelta
import argparse
import multiprocessing
from multiprocessing import Queue
from multiprocessing import Pipe
import time
from modules.markov_models_1 import __markov_models__
from os import listdir
from os.path import isfile, join
from ip_handler import IpHandler
import random

version = '0.4'

INFECTED = ["147.32.84.165"]
TW_TP = 0
TW_FN = 0
TW_FP = 0
TW_TN = 0
DETECTED_IP = set()
ALL_IP = set()
def timing(f):
    """ Function to measure the time another function takes."""
    def wrap(*args, **kwargs):
        time1 = time.time()
        ret = f(*args, **kwargs)
        time2 = time.time()
        print '%s function took %0.3f ms' % (f.func_name, (time2-time1)*1000.0)
        return ret
    return wrap

#Connection
class Connection(object):
    """ The class to simply handle tuples """
    def __init__(self, tuple4):
        self.id = tuple4
        self.amount_of_flows = 0
        self.src_ip = tuple4.split('-')[0]
        self.dst_ip = tuple4.split('-')[1]
        self.protocol = tuple4.split('-')[3]
        self.state_so_far = ""
        self.winner_model_id = False
        self.winner_model_distance = float('inf')
        self.proto = ""
        self.datetime = ""
        self.T1 = False
        self.T2 = False
        self.TD = False
        self.current_size = -1
        self.current_duration = -1
        self.previous_size = -1
        self.previous_duration = -1
        self.previous_time = -1
        # Thresholds
        self.tto = timedelta(seconds=3600)
        self.tt1 = float(1.05)
        self.tt2 = float(1.3)
        self.tt3 = float(5)
        self.td1 = float(0.1)
        self.td2 = float(10)
        self.ts1 = float(250)
        self.ts2 = float(1100)
        # The state
        self.state = ""
        # Final values for getting the state
        self.duration = -1
        self.size = -1
        self.periodic = -1
        self.color = str
        # By default print all tuples. Depends on the arg
        self.should_be_printed = True
        self.desc = ''
        # After a tuple is detected, min_state_len holds the lower letter position in the state
        # where the detection happened.
        self.min_state_len = 0
        # After a tuple is detected, max_state_len holds the max letter position in the state
        # where the detection happened. The new arriving letters to be detected are between max_state_len and the real end of the state
        self.max_state_len = 0
        self.detected_label = False

    def set_detected_label(self, label):
        self.detected_label = label

    def unset_detected_label(self):
        self.detected_label = False

    def get_detected_label(self):
        return self.detected_label

    def get_state_detected_last(self):
        if self.max_state_len == 0:
            # First time before any detection
            return self.state[self.min_state_len:]
        # After the first detection
        return self.state[self.min_state_len:self.max_state_len]

    def set_min_state_len(self, state_len):
        self.min_state_len = state_len

    def get_min_state_len(self):
        return self.min_state_len

    def set_max_state_len(self, state_len):
        self.max_state_len = state_len

    def get_max_state_len(self):
        return self.max_state_len

    def get_protocol(self):
        return self.protocol

    def get_state(self):
        return self.state

    def set_verbose(self, verbose):
        self.verbose = verbose

    def set_debug(self, debug):
        self.debug = debug

    def add_new_flow(self, column_values):
        """ Add new stuff about the flow in this tuple """
        # 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
        # Store previous
        self.previous_size = self.current_size
        self.previous_duration = self.current_duration
        self.previous_time = self.datetime
        if self.debug > 2:
            print 'Adding flow {}'.format(column_values)
        # Get the starttime
        self.datetime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
        # Get the size
        try:
            self.current_size = float(column_values[12])
        except ValueError:
            # It can happen that we dont have this value in the binetflow
            self.current_size = 0.0
        # Get the duration
        try:
            self.current_duration = float(column_values[1])
        except ValueError:
            # It can happen that we dont have this value in the binetflow
            self.current_duration = 0.0
        # Get the protocol
        self.proto = str(column_values[2])
        # Get the amount of flows
        self.amount_of_flows += 1
        # Update value of T1
        self.T1 = self.T2
        try:
            # Update value of T2
            self.T2 = self.datetime - self.previous_time
            # Are flows sorted?
            if self.T2.total_seconds() < 0:
                # Flows are not sorted
                if self.debug > 2:
                    print '@',
                # What is going on here when the flows are not ordered?? Are we losing flows?
        except TypeError:
            self.T2 = False
        # Compute the rest
        self.compute_periodicity()
        self.compute_duration()
        self.compute_size()
        self.compute_state()
        self.compute_symbols()
        if self.debug > 4:
            print '\tConnection {}. Amount of flows so far: {}'.format(self.get_id(), self.amount_of_flows)

    def compute_periodicity(self):
        # If either T1 or T2 are False
        if (isinstance(self.T1, bool) and self.T1 == False) or (isinstance(self.T2, bool) and self.T2 == False):
            self.periodicity = -1
        elif self.T2 >= self.tto:
            t2_in_hours = self.T2.total_seconds() / self.tto.total_seconds()
            # Should be int always
            for i in range(int(t2_in_hours)):
                self.state += '0'
        elif self.T1 >= self.tto:
            t1_in_hours = self.T1.total_seconds() / self.tto.total_seconds()
            # Should be int always
            for i in range(int(t1_in_hours)):
                self.state += '0'
        if not isinstance(self.T1, bool) and not isinstance(self.T2, bool):
            try:
                if self.T2 >= self.T1:
                    self.TD = timedelta(seconds=(self.T2.total_seconds() / self.T1.total_seconds())).total_seconds()
                else:
                    self.TD = timedelta(seconds=(self.T1.total_seconds() / self.T2.total_seconds())).total_seconds()
            except ZeroDivisionError:
                self.TD = 1
            # Decide the periodic based on TD and the thresholds
            if self.TD <= self.tt1:
                # Strongly periodic
                self.periodic = 1
            elif self.TD < self.tt2:
                # Weakly periodic
                self.periodic = 2
            elif self.TD < self.tt3:
                # Weakly not periodic
                self.periodic = 3
            else:
                self.periodic = 4
        if self.debug > 3:
            print '\tPeriodic: {}'.format(self.periodic)

    def compute_duration(self):
        if self.current_duration <= self.td1:
            self.duration = 1
        elif self.current_duration > self.td1 and self.current_duration <= self.td2:
            self.duration = 2
        elif self.current_duration > self.td2:
            self.duration = 3
        if self.debug > 3:
            print '\tDuration: {}'.format(self.duration)

    def compute_size(self):
        if self.current_size <= self.ts1:
            self.size = 1
        elif self.current_size > self.ts1 and self.current_size <= self.ts2:
            self.size = 2
        elif self.current_size > self.ts2:
            self.size = 3
        if self.debug > 3:
            print '\tSize: {}'.format(self.size)

    def compute_state(self):
        if self.periodic == -1:
            if self.size == 1:
                if self.duration == 1:
                    self.state += '1'
                elif self.duration == 2:
                    self.state += '2'
                elif self.duration == 3:
                    self.state += '3'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += '4'
                elif self.duration == 2:
                    self.state += '5'
                elif self.duration == 3:
                    self.state += '6'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += '7'
                elif self.duration == 2:
                    self.state += '8'
                elif self.duration == 3:
                    self.state += '9'
        elif self.periodic == 1:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'a'
                elif self.duration == 2:
                    self.state += 'b'
                elif self.duration == 3:
                    self.state += 'c'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'd'
                elif self.duration == 2:
                    self.state += 'e'
                elif self.duration == 3:
                    self.state += 'f'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'g'
                elif self.duration == 2:
                    self.state += 'h'
                elif self.duration == 3:
                    self.state += 'i'
        elif self.periodic == 2:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'A'
                elif self.duration == 2:
                    self.state += 'B'
                elif self.duration == 3:
                    self.state += 'C'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'D'
                elif self.duration == 2:
                    self.state += 'E'
                elif self.duration == 3:
                    self.state += 'F'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'G'
                elif self.duration == 2:
                    self.state += 'H'
                elif self.duration == 3:
                    self.state += 'I'
        elif self.periodic == 3:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'r'
                elif self.duration == 2:
                    self.state += 's'
                elif self.duration == 3:
                    self.state += 't'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'u'
                elif self.duration == 2:
                    self.state += 'v'
                elif self.duration == 3:
                    self.state += 'w'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'x'
                elif self.duration == 2:
                    self.state += 'y'
                elif self.duration == 3:
                    self.state += 'z'
        elif self.periodic == 4:
            if self.size == 1:
                if self.duration == 1:
                    self.state += 'R'
                elif self.duration == 2:
                    self.state += 'S'
                elif self.duration == 3:
                    self.state += 'T'
            elif self.size == 2:
                if self.duration == 1:
                    self.state += 'U'
                elif self.duration == 2:
                    self.state += 'V'
                elif self.duration == 3:
                    self.state += 'W'
            elif self.size == 3:
                if self.duration == 1:
                    self.state += 'X'
                elif self.duration == 2:
                    self.state += 'Y'
                elif self.duration == 3:
                    self.state += 'Z'

    def compute_symbols(self):
        if not isinstance(self.T2, bool):
            if self.T2 <= timedelta(seconds=5):
                self.state += '.'
            elif self.T2 <= timedelta(seconds=60):
                self.state += ','
            elif self.T2 <= timedelta(seconds=300):
                self.state += '+'
            elif self.T2 <= timedelta(seconds=3600):
                self.state += '*'
        if self.debug > 3:
            print '\tTD:{}, T2:{}, T1:{}, State: {}'.format(self.TD, self.T2, self.T1, self.state)

    def get_id(self):
        return self.id

    def __repr__(self):
        return('{} [{}] ({}): {}'.format(self.color(self.get_id()), self.desc, self.amount_of_flows, self.state))

    def print_tuple_detected(self):
        """
        Print the tuple. The state is the state since the last detection of the tuple. Not everything
        """
        #return('{} [{}] ({}): {}  Detected as: {}'.format(self.color(self.get_id()), self.desc, self.amount_of_flows, self.get_state_detected_last(), self.get_detected_label()))        
        return('{} [{}] ({}): Detected as: {}'.format(self.color(self.get_id()), self.desc, self.amount_of_flows, self.get_detected_label()))

    def set_color(self, color):
        self.color = color

# Process
class Processor(multiprocessing.Process):
    """ A class process to run the process of the flows """
    def __init__(self, queue, slot_width, get_whois, verbose, amount, dontdetect, threshold, debug, whitelist, classifier, sdw_width):
        multiprocessing.Process.__init__(self)
        self.get_whois = get_whois
        self.verbose = verbose
        self.debug = debug
        # The amount of letters requested to print minimum
        self.amount = amount
        self.queue = queue
        
        self.tuples = {}
        self.tuples_in_this_time_slot = {}

        self.slot_starttime = -1
        self.slot_endtime = -1
        self.slot_width = slot_width
        
        self.dontdetect = dontdetect
        self.ip_handler = IpHandler(self.verbose, self.debug,self.get_whois, classifier,sdw_width)

        self.ip_whitelist = whitelist
        #register signal for interrupting
        signal.signal(signal.SIGINT,self.handle_signal)

    def handle_signal(self, signal, frame):
        """Asynchronous interruption of the program"""
        self.queue.close()
        self.ip_handler.print_alerts()
        sys.exit(0)

    def get_tuple(self, tuple4):
        """ Get the values and return the correct tuple for them """
        try:
            tuple = self.tuples[tuple4]
            # We already have this connection
        except KeyError:
            # First time for this connection
            tuple = Connection(tuple4)
            tuple.set_verbose(self.verbose)
            tuple.set_debug(self.debug)
            self.tuples[tuple4] = tuple
        return tuple

    def process_out_of_time_slot(self, column_values, last_tw = False):
        """
        Process the tuples when we are out of the time slot
        last_tw specifies if we know this is the last time window. So we don't add the flow into the 'next' one. There was a problem were we store the last flow twice.
        """
        try:
            # Outside the slot
            if self.verbose > 1:
                print cyan('Time Window Started: {}, finished: {}. ({} connections)'.format(self.slot_starttime, self.slot_endtime, len(self.tuples_in_this_time_slot)))
            # Process all the addresses in this time window
            self.ip_handler.process_timewindow(self.slot_starttime, self.slot_endtime)
            """
            # After each timeslot finishes forget the tuples that are too big. This is useful when a tuple has a very very long state that is not so useful to us. Later we forget it when we detect it or after a long time.
            ids_to_delete = []
            for tuple in self.tuples:
                # We cut the strings of letters regardless of it being detected before.
                if self.tuples[tuple].amount_of_flows > 100:
                    if self.debug > 3:
                           print 'Delete all the letters because there were more than 100 and it was detected. Start again with this tuple.'
                    ids_to_delete.append(self.tuples[tuple].get_id())
            # Actually delete them
            for id in ids_to_delete:
                del self.tuples[id]
            """
            # Move the time window times
            self.slot_starttime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
            self.slot_endtime = self.slot_starttime + self.slot_width
            #clean the dictionary with active connections
            self.tuples_in_this_time_slot = {}

            # If not the last TW. Put the last flow received in the next slot, because it overcome the threshold and it was not processed
            if not last_tw:
                tuple4 = column_values[3]+'-'+column_values[6]+'-'+column_values[7]+'-'+column_values[2]
                tuple = self.get_tuple(tuple4)
                tuple.add_new_flow(column_values)
                # Detect the first flow of the future timeslot
                self.detect(tuple)
                self.tuples_in_this_time_slot[tuple.get_id()] = tuple 
                flowtime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
                # Ask for the IpAddress object for this source IP
                ip_address = self.ip_handler.get_ip(column_values[3])
                # Store detection result into Ip_address
                ip_address.add_detection(tuple.detected_label, tuple.id, tuple.current_size, flowtime, column_values[6], tuple.get_state_detected_last())
        except Exception as inst:
            print 'Problem in process_out_of_time_slot() in class Processor'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            exit(-1)

    def detect(self, tuple):
        """
        Detect behaviors
        """
        try:
            if not self.dontdetect:
                (detected, label, statelen) = __markov_models__.detect(tuple, self.verbose, self.debug)
                tuple.should_be_printed = True
                if detected:
                    # Change color
                    tuple.set_color(magenta)
                    # Set the detection label
                    tuple.set_detected_label(label)
                    """
                    # Set the detection state len
                    tuple.set_best_model_matching_len(statelen)

                    """
                    #print tuple.state[:statelen]
                    #print tuple.state[len(tuple.state)-statelen:-1]
                    if self.debug > 5:
                        print 'Last flow: Detected with {}'.format(label)
                    # Play sound
                    if args.sound:
                        pygame.mixer.music.play()
                elif not detected:
                    # Not detected by any reason. No model matching but also the state len is too short.
                    tuple.unset_detected_label()
                    if self.debug > 5:
                        print 'Last flow: Not detected'
        except Exception as inst:
            print '\tProblem with detect()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)

    def run(self):
        try:
            while True:
                if not self.queue.empty():
                    line = self.queue.get()
                    if 'stop' != line:
                        # Process this flow
                        nline = ','.join(line.strip().split(',')[:13])
                        try:
                            column_values = nline.split(',')
                            # 0:starttime, 1:dur, 2:proto, 3:saddr, 4:sport, 5:dir, 6:daddr: 7:dport, 8:state, 9:stos,  10:dtos, 11:pkts, 12:bytes
                            # check if ip is not in whitelist
                            if not column_values[3] in self.ip_whitelist:
                                if self.slot_starttime == -1:
                                    # First flow
                                    try:
                                        self.slot_starttime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
                                    except ValueError:
                                        continue
                                    self.slot_endtime = self.slot_starttime + self.slot_width
                                flowtime = datetime.strptime(column_values[0], '%Y/%m/%d %H:%M:%S.%f')
                                if flowtime >= self.slot_starttime and flowtime < self.slot_endtime:
                                    # Inside the slot
                                    tuple4 = column_values[3]+'-'+column_values[6]+'-'+column_values[7]+'-'+column_values[2]
                                    tuple = self.get_tuple(tuple4)
                                    self.tuples_in_this_time_slot[tuple.get_id()] = tuple                                
                                    tuple.add_new_flow(column_values)
                                    # After the flow has been added to the tuple, only work with the ones having more than X amount of flows
                                    if len(tuple.state) >= self.amount:
                                        # Detection
                                        self.detect(tuple)
                                        # Ask for IpAddress object 
                                        ip_address = self.ip_handler.get_ip(column_values[3])
                                        # Store detection result into Ip_address
                                        ip_address.add_detection(tuple.detected_label, tuple.id, tuple.current_size, flowtime,column_values[6], tuple.get_state_detected_last())
                                elif flowtime > self.slot_endtime:
                                    # Out of time slot
                                    self.process_out_of_time_slot(column_values, last_tw = False)
                            else:
                                if self.debug:
                                    print blue("Skipping flow with whitelisted ip: {}".format(column_values[3]))
                        except UnboundLocalError:
                            print 'Probably empty file.'
                    else:
                        try:
                            # Process the last flows in the last time slot
                            self.process_out_of_time_slot(column_values, last_tw = True)
                            # Print final Alerts
                            self.ip_handler.print_alerts()
                        except UnboundLocalError:
                            print 'Probably empty file...'
                            # Here for some reason we still miss the last flow. But since is just one i will let it go for now.
                        # Just Return
                        return True
        except Exception as inst:
            print '\tProblem with Processor()'
            print type(inst)     # the exception instance
            print inst.args      # arguments stored in .args
            print inst           # __str__ allows args to printed directly
            sys.exit(1)


####################
# Main
####################
def signal_handler(signal, frame):
    print magenta("\nInterrupting slips")
    #signal will be processed in the child process
    pass
        

if __name__ == '__main__':  
    print 'Stratosphere Linux IPS. Version {}'.format(version)
    print('https://stratosphereips.org\n')

    # Parse the parameters
    parser = argparse.ArgumentParser()
    parser.add_argument('-a', '--amount', help='Minimum amount of flows that should be in a tuple to be printed.', action='store', required=False, type=int, default=-1)
    parser.add_argument('-v', '--verbose', help='Amount of verbosity. This shows more info about the results.', action='store', default=1, required=False, type=int)
    parser.add_argument('-e', '--debug', help='Amount of debugging. This shows inner information about the flows.', action='store', default=0, required=False, type=int)
    parser.add_argument('-w', '--width', help='Width of the time slot used for the analysis. In minutes.', action='store', default=5, required=False, type=int)
    parser.add_argument('-d', '--datawhois', help='Get and show the WHOIS info for the destination IP in each tuple', action='store_true', default=False, required=False)
    parser.add_argument('-D', '--dontdetect', help='Dont detect the malicious behavior in the flows using the models. Just print the connections.', default=False, action='store_true', required=False)
    parser.add_argument('-f', '--folder', help='Folder with models to apply for detection.', action='store', required=False)
    parser.add_argument('-s', '--sound', help='Play a small sound when a periodic connections is found.', action='store_true', default=False, required=False)
    parser.add_argument('-t', '--threshold', help='Threshold for detection with IPHandler', action='store', default=0.002, required=False, type=float)
    parser.add_argument('-W', '--whitelist', help="File with the IP addresses to whitelist. One per line.", action='store', required=False)
    parser.add_argument('-c', '--classifier', help="File where serialized classifier.", action='store',required=False, default="classifier.pickle", type=str)
    parser.add_argument('-hr', '--history_range', help='Number of previous time winddows used ind the SDW', action='store', default=12, required=False, type=int)

    args = parser.parse_args()

    # Check the verbose level
    if args.verbose < 1:
        args.verbose = 1

    # Check the debug level
    if args.debug < 0:
        args.debug = 0

    if args.dontdetect:
        print 'Warning: No detections will be done. Only the behaviors are printed.'
        print
        # If the folder with models was specified, just ignore it
        args.folder = False

    # Do we need sound?
    if args.sound:
        import pygame.mixer
        pygame.mixer.init(44100)
        pygame.mixer.music.load('periodic.ogg')


    # Read the folder with models if specified
    if args.folder:
        onlyfiles = [f for f in listdir(args.folder) if isfile(join(args.folder, f))]
        if args.verbose > 2:
            print 'Detecting malicious behaviors with the following models:'
        for file in onlyfiles:
            __markov_models__.set_verbose(args.verbose)
            __markov_models__.set_debug(args.debug)
            __markov_models__.set_model_to_detect(join(args.folder, file))

    # Create the queue
    queue = Queue()

    # Read whitelist
    whitelist = set()
    if args.whitelist:
        try:
            content = set(line.rstrip('\n') for line in open(args.whitelist))
            if len(content) > 0:
                if args.verbose > 1:
                    print blue("Whitelisted IPs:")
                for item in content:
                    if args.verbose > 1:
                        print blue("\t" + item)
                whitelist = content
        except Exception as e:
            print blue("Whitelist file '{}' not found!".format(args.whitelist))


    # Create the thread and start it
    processorThread = Processor(queue, timedelta(minutes=args.width), args.datawhois, args.verbose, args.amount, args.dontdetect, args.threshold, args.debug, whitelist,args.classifier, args.history_range)
    
    #start the process
    processorThread.start()
    #register signal handler in parent process
    signal.signal(signal.SIGINT,signal_handler)

    # Just put the lines in the queue as fast as possible
    for line in sys.stdin:
            #print line
            queue.put(line)
    if args.verbose > 2:
        print 'Finished receiving the input.'
    # Shall we wait? Not sure. Seems that not
    time.sleep(1)
    queue.put('stop')

    #merge the processes
    processorThread.join()

    #exit
    print "\nExiting Stratosphere IPS."

