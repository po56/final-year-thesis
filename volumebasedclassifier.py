from sklearn import svm
from sklearn import cross_validation

X = []
Y = []

#open the training document

with open ("/home/patrick/Documents/dev/FinalYearProject/sampletest", "r") as trainingdata:
    for line in trainingdata:
        currentSample = line.split(",")
        Y.append(currentSample.pop().replace('\n', ''))
        X.append(currentSample)
print(X)
print(Y)

#perform some cross validation scoring to give us a rough idea of the classifier accuracy
X_train, X_test, y_train, y_test = cross_validation.train_test_split(
X, Y , test_size=0.4, random_state=0)

#c parameter influences the size of the seperating hyperplane. Larer value = smaller hyperplane and visa versa
clf = svm.SVC(C=4, kernel= 'liner', probability= False)
crossvalaccuracy = clf.fit(X_train, y_train).score(X_test, y_test)






















