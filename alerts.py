#!/usr/bin/python -u
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

from datetime import datetime
from time import gmtime, strftime
from colors import *

class Alert(object):
    """Basic object of type Alert. DO NOT CREATE INSTANCES OF THIS CLASS - use derived classes instead!"""
    def __init__(self, time,source):
        self.time = time
        self.source = source
    def __str__(self):
        print "function print_alert() has to be implemented in derived class!"
        return  NotImplemented

class IpDetectionAlert(Alert):
    def __init__(self, time, source, vector):
        super(IpDetectionAlert, self).__init__(time,source)
        self.vector = vector

    def __str__(self):
        return yellow('*time: {}\t features:{}*'.format(self.time.strftime('%Y/%m/%d %H:%M:%S'),self.vector))
