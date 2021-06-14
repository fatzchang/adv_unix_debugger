EXEC	= hw4
CPP		= g++

all: $(EXEC)


$(EXEC):
	$(CPP) -o $(EXEC) debugger.cpp

