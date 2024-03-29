#usr/bin/python

from sklearn import svm
from sklearn import cross_validation
import sys
import socket
import os
import numpy as np


def main():

	X = []
	Y = []

	server_address = '/HTTPListener'
	#remove any previous instances of the socket, in case the program did not close correctly. 
	try:
		os.remove(server_address)
	except OSError:
		pass 
	sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
	print 'created socket'
	sock.bind(server_address)
	print 'socket bound'

	#open the training document

	with open ("HTTPstats", "r") as HTTPNorms:
	    for line in HTTPNorms:
		currentSample = line.split(",")
		X.append(currentSample)

	#c parameter influences the size of the seperating hyperplane. Larer value = smaller hyperplane and visa versa
	clf = svm.OneClassSVM(kernel= 'linear',nu = 0.2)

	clf.fit(X)

	sock.listen(1)

	while 1:
		connection ,client_addr = sock.accept()
		
		while 1:
			data = connection.recv(1024)
			if not data:
				break
			print data
			formattedList = [float(x) for x in data.split(",")]
			result = clf.predict(formattedList).item(0)
			resultstring = "%.1f" % result
			print resultstring
			connection.send(resultstring)
				
		
		connection.close()

	#predicting the output based on the training data

	

	



if __name__ == '__main__':
    main()

