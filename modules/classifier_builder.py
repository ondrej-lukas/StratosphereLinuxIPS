#!/usr/bin/python
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

import sys
from matplotlib.colors import Normalize
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import GradientBoostingClassifier
import pickle
import argparse
import csv
import random
import numpy as np
import matplotlib.pyplot as plt
from sklearn.datasets import load_digits
from sklearn.model_selection import *
from xgboost import XGBClassifier
import xgboost as xgb
from sklearn.naive_bayes import GaussianNB

def separate_labels(dataset, number_of_features):
	"""Trims dataset and divides features and labels"""
	vectors = []
	labels = []
	for row in dataset:
		labels.append(row[-1])
		if number_of_features > 0:
			index = 4 + number_of_features
			vectors.append(row[4:number_of_features])
		else:
			vectors.append(row[4:-1])
	return (vectors, labels)

def plot_learning_curve(estimator, title, X, y, ylim=None, cv=None,n_jobs=1, train_sizes=np.linspace(.1, 1.0, 5)):
    """
    Generate a simple plot of the test and training learning curve.

    Parameters
    ----------
    estimator : object type that implements the "fit" and "predict" methods
        An object of that type which is cloned for each validation.

    title : string
        Title for the chart.

    X : array-like, shape (n_samples, n_features)
        Training vector, where n_samples is the number of samples and
        n_features is the number of features.

    y : array-like, shape (n_samples) or (n_samples, n_features), optional
        Target relative to X for classification or regression;
        None for unsupervised learning.

    ylim : tuple, shape (ymin, ymax), optional
        Defines minimum and maximum yvalues plotted.

    cv : int, cross-validation generator or an iterable, optional
        Determines the cross-validation splitting strategy.
        Possible inputs for cv are:
          - None, to use the default 3-fold cross-validation,
          - integer, to specify the number of folds.
          - An object to be used as a cross-validation generator.
          - An iterable yielding train/test splits.

        For integer/None inputs, if ``y`` is binary or multiclass,
        :class:`StratifiedKFold` used. If the estimator is not a classifier
        or if ``y`` is neither binary nor multiclass, :class:`KFold` is used.

        Refer :ref:`User Guide <cross_validation>` for the various
        cross-validators that can be used here.

    n_jobs : integer, optional
        Number of jobs to run in parallel (default 1).
    """
    plt.figure()
    plt.title(title)
    #if ylim is not None:
        #plt.ylim(*ylim)
    plt.xlabel("Training examples")
    plt.ylabel("Score")
    train_sizes, train_scores, test_scores = learning_curve(
        estimator, X, y, cv=cv, n_jobs=n_jobs, train_sizes=train_sizes)
    train_scores_mean = np.mean(train_scores, axis=1)
    train_scores_std = np.std(train_scores, axis=1)
    test_scores_mean = np.mean(test_scores, axis=1)
    test_scores_std = np.std(test_scores, axis=1)
    plt.grid()

    plt.fill_between(train_sizes, train_scores_mean - train_scores_std,
                     train_scores_mean + train_scores_std, alpha=0.1,
                     color="r")
    plt.fill_between(train_sizes, test_scores_mean - test_scores_std,
                     test_scores_mean + test_scores_std, alpha=0.1, color="g")
    plt.plot(train_sizes, train_scores_mean, 'o-', color="r",
             label="Training score")
    plt.plot(train_sizes, test_scores_mean, 'o-', color="g",
             label="Cross-validation score")

    plt.legend(loc="best")
    return plt

def merge_datasets(datasets,filename):
	"""Merges several detasets in the csv format into one"""
	dataset = open(filename,'a')
	for item in datasets:
		f = open(item,"rb")
		for line in f:
			dataset.write(line)
	dataset.close()

if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--filename', help='File to store the created Random Forest', action='store', required=False, type=str, default="classifier.pickle")
	parser.add_argument('-d','--dataset', help="File with training data (.csv)", action="store", required=True, type=str)
	parser.add_argument('-n','--number_of_features', help="Lenngth of the feature vector", action="store", required=False, type=int, default=-1)
	parser.add_argument('-r', '--report', help='Generate repor', action='store_true', default=False, required=False)
	args = parser.parse_args()

	#load datamatrix from the file
	data_matrix = []
	with open(args.dataset, 'rb') as csvfile:
		dataset = csv.reader(csvfile,delimiter=',', quotechar='|')
		for row in dataset:
			data_matrix.append(row)
	#shuffle it randomly
	random.shuffle(data_matrix)
	#separate features and labels
	X, y = separate_labels(data_matrix,args.number_of_features)
	#convert to numpy array (required by clasifier)
	X = np.array(X).astype(np.float)
	y = np.array(y)
	#initialize classifier
	estimator = XGBClassifier(learning_rate =0.4, n_estimators=1000, max_depth=12, min_child_weight=1, gamma=0.3, subsample=0.8, colsample_bytree=0.7)
	#create the learning curve if requested
	if args.report:
		title = "Learnig curves"
		cv = ShuffleSplit(n_splits=100, test_size=0.2, random_state=0)
		plot_learning_curve(estimator, title, X, y, ylim=(0.7, 1.01), cv=cv, n_jobs=4)
	#train the classifier
	estimator.fit(X,y)
	#store it in the file
	pickle.dump(estimator, open(args.filename, "wb"))
	print "Classifier created and stored successfully in '{}'.".format(args.filename)
	try:
		with open(args.filename, 'r') as f:
			estimator2 = pickle.load(f)
			estimator2.predict(np.array([X[0]]))
			if args.report:
				plt.show()
			f.close()
	except Exception as inst:
	    print "\tprint Problem with the classifier stored in '{}' - loading was NOT successful!".format(args.filename)
	    print type(inst)     # the exception instance
	    print inst.args      # arguments stored in .args
	    print inst           # __str__ allows args to printed directly
	    sys.exit(1)