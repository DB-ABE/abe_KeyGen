.PHONY:all

m=$(wildcard ./main/*.o)
main=$(patsubst ./main/%.o, %, $(m))
src=$(wildcard ./src/*.o)

all:$(main)
$(main):
	$(CC) -o $(BIN_DIR)/$@ ./main/$@.o $(src) $(LIBS)

