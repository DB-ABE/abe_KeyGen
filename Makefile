.PHONY:all clean

##
PWD_DIR=$(shell pwd)
BIN_DIR=$(PWD_DIR)/bin
SRC_DIR=$(PWD_DIR)/src
OBJ_DIR=$(PWD_DIR)/obj
MAIN_DIR=$(PWD_DIR)/main
LIB_DIR=$(PWD_DIR)/lib 
INC_DIR=$(PWD_DIR)/include
##
CC=g++
CFLAG=-Wall -g -I$(INC_DIR)
LIBS :=-pthread -fsanitize=address -lcrypto -lrelic -lrelic_ec -lopenabe -lssl -lmysqlclient -lcjson -ldl
##
export PWD_DIR SRC_DIR OBJ_DIR MAIN_DIR LIB_DIR INC_DIR CC CFLAG LIBS BIN_DIR

##
all:
	make -C $(SRC_DIR)
	make -C $(MAIN_DIR)
	make -C $(OBJ_DIR)
##
clean:
	rm -rf $(OBJ_DIR)/*.o
	rm -rf $(OBJ_DIR)/main/*.o
	rm -rf $(OBJ_DIR)/src/*.o
	rm -rf $(BIN_DIR)/*

#TEST: