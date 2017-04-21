#!/usr/bin/python
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz


import sys
from colors import *
from math import log
from sklearn.ensemble import RandomForestClassifier
import pickle
import argparse
import csv
import random
import numpy



def separate_labels(dataset):
	"""Trims dataset and divides features and labels"""
	vector = []
	labels = []
	for row in dataset:
		labels.append(row[-1])
		tmp  = []
		for i in range(4,17):
			tmp.append(float(row[i]))
		vector.append(tmp)
	return (vector, labels)


if __name__ == '__main__':

	
	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--filename', help='File to store the created Random Forest', action='store', required=False, type=str, default="rf_classifier.pickle")
	parser.add_argument('-d','--dataset', help="File with training data (.csv)", action="store", required=True, type=str)
	parser.add_argument('-e', '--n_estimators', help="Number of Decision trees in the RF", action="store", required=False, default=500, type=int)

	args = parser.parse_args()

	#create RF
	rf1 = RandomForestClassifier(args.n_estimators,verbose=0,n_jobs=-1)
	
	#load data	
	data_matrix = []
	with open(args.dataset, 'rb') as csvfile:
		dataset = csv.reader(csvfile,delimiter='\t', quotechar='|')
		for row in dataset:
			data_matrix.append(row)
	
	#randomly shuffle data
	random.shuffle(data_matrix)

	#slpit into training and testing set
	(X,Y) = separate_labels(data_matrix[:25000])
	(test_x,test_y) = separate_labels(data_matrix[25001:])
	
	#train
	rf1.fit(X,Y)
	
	#measure accuracy on testing set
	print "Accuracy: {}".format(rf1.score(test_x,test_y))

	#store the classifier into file
	rf_file = open(args.filename,'w')
	pickle.dump(rf1,rf_file)

	





	"""
	#MERGING partial datasets into one
	dataset = open("dataset.csv",'a')

	partial_dataset = ["./Dataset/CTU-Normal-6-filtered/data_matrix_CTU-Normal-6-filtered.csv","./Dataset/CTU-Normal-5/data_matrix_CTU-Normal-5.csv","./Dataset/CTU-Normal-4-only-DNS/data_matrix_CTU-Normal-4-only-DNS.csv","./Dataset/CTU-Malware-Capture-Botnet-100/data_matrix_CTU-Malware-Capture-Botnet-100.csv", "./Dataset/CTU-Malware-Capture-Botnet-221-2/data_matrix_CTU-Malware-Capture-Botnet-221-2.csv", "./Dataset/CTU-Malware-Capture-Botnet-119-2/data_matrix_CTU-Malware-Capture-Botnet-119-2.csv", "./Dataset/CTU-Malware-Capture-Botnet-244-1/data_matrix_CTU-Malware-Capture-Botnet-244-1.csv"]
	for item in partial_dataset:
		f = open(item,"rb")
		for line in f:
			dataset.write(line)
	dataset.close()
	"""


			


	