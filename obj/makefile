.PHONY:all

m=$(wildcard ./main/*.o)
main=$(patsubst ./main/%.o, %, $(m))
t=$(wildcard ./TEST/*.o)
TEST=$(patsubst ./TEST/%.o, %, $(t))
src=$(wildcard ./src/*.o)

all:$(main) $(TEST)
$(main):
	$(CC) -o $(BIN_DIR)/$@ ./main/$@.o $(src) $(LIBS) -lgtest -lgcov
$(TEST):
	$(CC) -o $(TEST_DIR)/bin/$@ ./TEST/$@.o $(src) $(LIBS) -lgtest -lgcov
# all:
# 	$(CC) -o $(BIN_DIR)/Keymanager ./main/Keymanager.o $(src) $(LIBS)
# 	$(CC) -o $(BIN_DIR)/Database ./main/Database.o $(src) $(LIBS)
# 	$(CC) -o $(BIN_DIR)/cert_server ./main/cert_server.o ./src/Config.o ./src/SSL_socket.o $(LIBS)
# 	$(CC) -o $(BIN_DIR)/cert_client ./main/cert_client.o ./src/Config.o ./src/SSL_socket.o $(LIBS)