
# Makefile
# Project manager file
# IPK project
# FIT VUT
# 2017/2018

# compile settings
cc = g++
defines = -DDEBUG_MODE
linkings = -lpthread -lm -lpcap
flags = $(defines) -std=c++11 -O2 -g -pedantic -Wall -Wextra

all: myripsniffer myripresponse

myripsniffer: myripsniffer.cpp
	@echo "Building $@.";\
	$(cc) $(flags) $< -o $@ $(linkings)

myripresponse: myripresponse.cpp
	@echo "Building $@.";\
	$(cc) $(flags) $< -o $@ $(linkings)


# doc
.PHONY: doc
doc:
	@echo "Create documentation.";\
	$(MAKE) -C doc/ -s

# clean
.PHONY: clean
clean:
	@echo "Cleaning generated files.";\
	rm -rf *~ *.o *.gch *.dep myripsniffer myripresponse xbenes49.zip
	@printf "";\
	$(MAKE) -C doc/ -s clean

# zip
.PHONY: zip
zip:
	@echo "Zipping files.";\
	#cp doc/manual.pdf .
	#@printf "";
	zip xbenes49.zip *.cpp *.h Makefile doc/* > /dev/null 2> /dev/null