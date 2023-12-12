.PHONY:all
src=$(wildcard ./*.cc)
objs=$(patsubst %.cc, %.o, $(src))

all:$(objs)

%.o:%.cc
	$(CC) -c $< -o $(OBJ_DIR)/main/$@ $(CFLAG)