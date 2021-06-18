EXEC	= hw4
CPP		= g++
FLAGS	= -DDEBUG=1
LIBS	= -lcapstone

INCL_DIR	= include
SRC_DIR		= src
BUILD_DIR	= build

ENTRY		= debugger
INCLS		= $(wildcard $(INCL_DIR)/*.hpp)
SRCS		= $(wildcard $(SRC_DIR)/*.cpp)

OBJS = $(SRCS:$(SRC_DIR)/%.cpp=$(BUILD_DIR)/%.o)
OBJS += $(BUILD_DIR)/$(ENTRY).o


all: $(EXEC)

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.cpp
	@mkdir -p $(@D)
	$(CPP) -c -I$(INCL_DIR) $(FLAGS) -o $@ $<

$(BUILD_DIR)/$(ENTRY).o: $(ENTRY).cpp
	$(CPP) -c -I$(INCL_DIR) $(FLAGS) -o $@ $<

$(EXEC): $(OBJS) $(INCLS)
	$(CPP) -o $(EXEC) -I$(INCL_DIR) $(FLAGS) $(OBJS) $(LIBS)

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
	rm -rf $(EXEC)