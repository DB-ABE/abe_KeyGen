.PHONY:all
src=$(wildcard ./*.cc)
objs=$(patsubst %.cc, %.o, $(src))

all:$(objs)

%.o:%.cc
	$(CC) -fprofile-arcs -ftest-coverage -c $< -o $(OBJ_DIR)/TEST/$@ $(CFLAG) 