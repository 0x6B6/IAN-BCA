CC = gcc
CFLAGS = -Wall -Wextra -Werror -Wpedantic

EXECUTABLE = ian-proj1
SOURCE = ian-proj1.c

TEST_DIR = test-files

all: $(EXECUTABLE)
	@echo "Project compiled successfuly!"

$(EXECUTABLE): $(SOURCE)
	$(CC) $(CFLAGS) -o $@ $^ -lelf

test: obj bin
	@echo "Test file compiled successfuly!"
obj:
	$(CC) $(TEST_DIR)/test.c -o $(TEST_DIR)/test.o -c

bin:
	$(CC) $(TEST_DIR)/test.c $(TEST_DIR)/extern.c -o $(TEST_DIR)/test

run:
	./$(EXECUTABLE) $(TEST_DIR)/test

tar:
	cd .. && tar -czvf ian/$(EXECUTABLE).tar.gz ian/*.c ian/Makefile ian/test-files

clean:
	rm -f $(EXECUTABLE) $(TEST_DIR)/test $(TEST_DIR)/*.o *.o $(EXECUTABLE).tar.gz
	rm -rf $(TEST_DIR)

.PHONY: all clean