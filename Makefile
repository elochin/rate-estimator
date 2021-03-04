ALL:
	gcc -Wall rate-estimator.c -o rate-estimator -lpcap

debug:
	gcc -g -Wall rate-estimator.c -o rate-estimator -lpcap
