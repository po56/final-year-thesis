#usr/bin/python

from sklearn import svm
from sklearn import cross_validation
import sys

def main():

	X = []
	Y = []

	#open the training document
	with open ("trainingdata", "r") as trainingdata:
	    for line in trainingdata:
		currentSample = line.split(",")
		X.append(currentSample)
		Y.append(currentSample.pop().replace('\n', ''))

	for item in Y:
	    if item == " NORMAL":
		item = 1
	    else:
		if item == " SYNFLOOOD":
		    item = 2

	clf = svm.SVC(kernel= 'linear', C=4)
	clf.fit(X, Y)

	userInput = sys.stdin.readline()

	formattedList = [float(x) for x in userInput.split(",")]

	#c parameter influences the size of the seperating hyperplane. Larer value = smaller hyperplane and visa versa
	clf = svm.SVC(kernel= 'linear', C=4)

	#cross validate for accuracy
	X_train, X_test, y_train, y_test = cross_validation.train_test_split(X, Y, test_size=0.6, random_state=0)

	clf.fit(X_train, y_train)

	score = clf.score(X_test, y_test)

	#fitting the whole training set for final classification

	clf.fit(X,Y)

	#predicting the output based on the training data

	sys.stdout.write(clf.predict(formattedList))

	sys.stdout.flush()

if __name__ == '__main__':
    main()

