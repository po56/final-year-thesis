# usr/bin/python

from sklearn import svm
from sklearn import cross_validation
from sklearn.grid_search import GridSearchCV
from sklearn.svm import SVC
from sklearn.metrics import classification_report
import sys
import socket
import os



def main():
    X = []
    Y = []


    C_vals = [1e-4, 1e-3, 1e-2,1e-1, 1e1, 1e2, 1e3, 1e4]

    # open the training document

    with open("trainingdata", "r") as trainingdata:
        for line in trainingdata:
            currentSample = line.split(",")
            X.append(currentSample)
            Y.append(currentSample.pop().replace('\n', ''))


            # c parameter influences the size of the seperating hyperplane. Larer value = smaller hyperplane and visa versa

    print "All data" + str(X)
    print len(X)
    print len(Y)
    print "All labels" + str(Y)

            # cross validate for accuracy
    X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, Y, test_size=0.4, random_state=0)

    print X_train
    print y_train

    # parameters to find the best SVM configuration
    params = [{'kernel': ['rbf'], 'gamma': [1e-3, 1e-4],
               'C': C_vals},
              {'kernel': ['linear'], 'C': C_vals, }, {'kernel':['linear'], 'C': C_vals, 'degree': [3]}]

    clf = GridSearchCV(SVC(C=1), params, cv=100)

    print "testing parameters"

    clf.fit(X_train, y_train)

    print "done fitting data"

    y_preds = clf.predict(X_test)

    print "predicting test data"

    for score in clf.grid_scores_:
        print score
    print("\n\n")
    print("best parameters:")
    print clf.best_params_

    print classification_report(y_test, y_preds)


if __name__ == '__main__':
    main()
