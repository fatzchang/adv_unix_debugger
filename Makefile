EXEC	= hw4
CPP		= g++

INCL_DIR	= include
SRC_DIR		= src
BUILD_DIR	= build

ENTRY		= debugger.cpp
INCLS		= $(wildcard $(INCL_DIR)/*.hpp)
SRCS		= $(wildcard $(SRC_DIR)/*.cpp)
SRCS += $(ENTRY)

all: $(EXEC)


$(EXEC): $(SRCS) $(INCLS)
	$(CPP) -o $(EXEC) -I$(INCL_DIR) $(SRCS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(EXEC)