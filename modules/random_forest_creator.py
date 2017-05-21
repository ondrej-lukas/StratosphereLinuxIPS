#!/usr/bin/python
# This file is part of the Stratosphere Linux IPS
# See the file 'LICENSE' for copying permission.
#Author: Ondrej Lukas - ondrej.lukas95@gmail.com, lukasond@fel.cvut.cz

import sys
from math import log
from matplotlib.colors import Normalize
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from sklearn.ensemble import AdaBoostClassifier
from sklearn.ensemble import GradientBoostingClassifier
import pickle
import argparse
import csv
import random
import numpy
import numpy as np
import matplotlib.pyplot as plt
from sklearn.datasets import load_digits
from sklearn.model_selection import learning_curve
from sklearn.model_selection import ShuffleSplit
from sklearn.model_selection import train_test_split
from sklearn.metrics import confusion_matrix
from sklearn.neural_network import MLPClassifier
#from sklearn.metrics import confusion_matrix, mean_squared_error
from xgboost import XGBClassifier
import xgboost as xgb
from sklearn.naive_bayes import GaussianNB
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import GridSearchCV
from sklearn.model_selection import StratifiedShuffleSplit
from sklearn.model_selection import validation_curve
from sklearn.metrics import classification_report


# Utility function to move the midpoint of a colormap to be around
# the values of interest.

class MidpointNormalize(Normalize):

    def __init__(self, vmin=None, vmax=None, midpoint=None, clip=False):
        self.midpoint = midpoint
        Normalize.__init__(self, vmin, vmax, clip)

    def __call__(self, value, clip=None):
        x, y = [self.vmin, self.midpoint, self.vmax], [0, 0.5, 1]
        return np.ma.masked_array(np.interp(value, x, y))

def separate_labels(dataset):
	"""Trims dataset and divides features and labels"""
	vectors = []
	labels = []
	for row in dataset:
		labels.append(row[-1])
		#vectors.append(row[4:-1])
		vectors.append(row[4:16])
	return (vectors, labels)

def merge_lists(lists,exclude_index):
	l = []
	for i in range(0,len(lists)):
		if i != exclude_index:
			l = l + lists[i]
	return l

def plot_learning_curve(estimator, title, X, y, ylim=None, cv=None,
                        n_jobs=1, train_sizes=np.linspace(.1, 1.0, 5)):
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
	dataset = open(filename,'a')
	for item in datasets:
		f = open(item,"rb")
		for line in f:
			dataset.write(line)
	dataset.close()


def count_labels(dataset_filename):
	m = 0
	n = 0
	c = 0
	with open(dataset_filename, 'rb') as csvfile:
		dataset = csv.reader(csvfile,delimiter=',', quotechar='|')
		for row in dataset:
			c += 1
			if row[-1] == "Normal":
				n+=1
			else:
				m+=1
	print "{} count:{}, Normal:{}, Malicious:{}.".format(dataset_filename,c,n,m)


if __name__ == '__main__':

	parser = argparse.ArgumentParser()
	parser.add_argument('-f', '--filename', help='File to store the created Random Forest', action='store', required=False, type=str, default="classifier.pickle")
	parser.add_argument('-d','--dataset', help="File with training data (.csv)", action="store", required=True, type=str)
	parser.add_argument('-u', '--update_tree', help="Pickle file with RF to be updated", action="store", required=False, type=str, default="")
	parser.add_argument('-r', '--report', help="Create report from crossvalidation",action='store_true', required=False, default=False)
	args = parser.parse_args()


	"""
	partial_datasets = ["CTU-Malware-Capture-Botnet-100_datamatrix_tw_sdw.csv", "CTU-Malware-Capture-Botnet-47_datamatrix_tw_sdw_Infected.csv", "CTU-Normal-3-Public_datamatrix_tw_sdw.csv",
	"CTU-Malware-Capture-Botnet-119-2_datamatrix_tw_sdw.csv", "CTU-Malware-Capture-Botnet-47_datamatrix_tw_sdw_Normal.csv", "CTU-Normal-4-only-DNS_datamatrix_tw_sdw.csv",
	"CTU-Malware-Capture-Botnet-221-2_datamatrix_tw_sdw.csv", "CTU-Malware-Capture-Botnet-49_datamatrix_tw_sdw.csv", "CTU-Normal-5_datamatrix_tw_sdw.csv",
	"CTU-Malware-Capture-Botnet-244-1_datamatrix_tw_sdw.csv", "CTU-Malware-Capture-Botnet-50_datamatrix_tw_sdw_normal.csv", "CTU-Normal-6-filtered_datamatrix_tw_sdw.csv"]
	
	merge_datasets(partial_datasets, "dataset.csv")
	"""

	"""
	prefix = "../Dataset/train_data/data_matrices/"
	for item in partial_dataset:
		count_labels(prefix + item)
	"""
	#load data	
	data_matrix = []
	with open(args.dataset, 'rb') as csvfile:
		dataset = csv.reader(csvfile,delimiter=',', quotechar='|')
		for row in dataset:
			data_matrix.append(row)
	
	random.shuffle(data_matrix)
	X, y = separate_labels(data_matrix[:10000])
	X = numpy.array(X)
	y = numpy.array(y)



	X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.4, random_state=0)

	# Set the parameters by cross-validation
	tuned_parameters = [{'n_estimators': [200, 400,600, 800, 1000,1200], 'max_depth': [4, 8,12,16,24,32]}]

	scores = ['accuracy']
	print "SVM"

	tuned_parameters = [{'kernel': ['rbf'], 'gamma': [1e-3, 1e-4,1e-5],'C': [1, 10, 100, 1000]}, {'kernel': ['linear'], 'C': [1, 10, 100, 1000]}]
   	for score in scores:
	    print("# Tuning hyper-parameters for %s" % score)
	    print()

	    clf = GridSearchCV(SVC(C=1), tuned_parameters, cv=5,
	                       scoring=score)
	    clf.fit(X_train, y_train)

	    print("Best parameters set found on development set:")
	    print()
	    print(clf.best_params_)
	    print()
	    print("Grid scores on development set:")
	    print()
	    means = clf.cv_results_['mean_test_score']
	    stds = clf.cv_results_['std_test_score']
	    for mean, std, params in zip(means, stds, clf.cv_results_['params']):
	        print("%0.3f (+/-%0.03f) for %r"
	              % (mean, std * 2, params))
	    print()

	    print("Detailed classification report:")
	    print()
	    print("The model is trained on the full development set.")
	    print("The scores are computed on the full evaluation set.")
	    print()
	    y_true, y_pred = y_test, clf.predict(X_test)
	    print(classification_report(y_true, y_pred))
	    print()
	"""
	print "XGbost"


	tuned_parameters = [{'n_estimators': [200, 400,600, 800, 1000,1200], 'max_depth': [4, 8,12,16,24], 'gamma': [0.1, 0.2, 0.3, 0.4, 0.5, 0.6,0.8 ], 'subsample' : [0.2,0.4,0.6,0.8],'learning_rate' : [0.2,0.4,0.6,0.8]}]

	scores = ['accuracy']
	print "RANDOM FORREST"
	for score in scores:
	    print("# Tuning hyper-parameters for %s" % score)
	    print()

	    clf = GridSearchCV(XGBClassifier(min_child_weight=1), tuned_parameters, cv=5,
	                       scoring=score)
	    clf.fit(X_train, y_train)

	    print("Best parameters set found on development set:")
	    print()
	    print(clf.best_params_)
	    print()
	    print("Grid scores on development set:")
	    print()
	    means = clf.cv_results_['mean_test_score']
	    stds = clf.cv_results_['std_test_score']
	    for mean, std, params in zip(means, stds, clf.cv_results_['params']):
	        print("%0.3f (+/-%0.03f) for %r"
	              % (mean, std * 2, params))
	    print()

	    print("Detailed classification report:")
	    print()
	    print("The model is trained on the full development set.")
	    print("The scores are computed on the full evaluation set.")
	    print()
	    y_true, y_pred = y_test, clf.predict(X_test)
	    print(classification_report(y_true, y_pred))
	    print()
	"""	
	"""
	title = "Learning Curves XGB lr=0.4 $\gamma$=0.3, e=1000, md=12 cb=07"
	cv = ShuffleSplit(n_splits=10, test_size=0.2, random_state=0)
	estimator = XGBClassifier(learning_rate =0.4, n_estimators=1000, max_depth=12, min_child_weight=1, gamma=0.3, subsample=0.8, colsample_bytree=0.7)
	plot_learning_curve(estimator, title, X, y, (0.7, 1.01), cv=cv, n_jobs=4)
	plt.savefig('./images/XGB_lr_04_gamma_03_e_1000_md_08_cb_07_SDW.png',dpi=400, bbox_inches='tight')
	plt.show()

	
	estimator = XGBClassifier(learning_rate =0.4, n_estimators=1000, max_depth=12, min_child_weight=1, gamma=0.3, subsample=0.8, colsample_bytree=0.7)
	estimator.fit(X,y)
	xgb.plot_importance(estimator)
	pickle.dump(estimator, open(args.filename, "wb"))
	print "Classifier stored successfully."

	with open(args.filename, 'r') as f:
		estimator2 = pickle.load(f)
		f.close()
	print "Classifier loaded successfully."
	print estimator2.predict(numpy.array([X[0]]))
	"""