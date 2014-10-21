CC=xcrun -sdk macosx clang
BIN=bin
OBJ=obj

output_dirs:
	mkdir -p $(BIN); mkdir -p $(OBJ)

all: tests

tests: base64_test repeating_key_xor_test decrypt_single_char_xor_test xor_buffers_test
	$(BIN)/hex_to_base64 && $(BIN)/xor_buffers && $(BIN)/decrypt_single_char_xor && $(BIN)/decrypt_single_char_xor input_4.txt && $(BIN)/repeating_key_xor input_6.txt decrypted_6.txt

base64_test: output_dirs hex_to_base64.c
	$(CC) -DBASE64_TEST -o $(BIN)/hex_to_base64 hex_to_base64.c

base64.o: output_dirs hex_to_base64.c
	$(CC) -o $(OBJ)/hex_to_base64.o -c hex_to_base64.c

decrypt_single_char_xor_test: output_dirs base64.o decrypt_single_char_xor.c
	$(CC) -DDECRYPT_SINGLE_CHAR_XOR_TEST -o $(BIN)/decrypt_single_char_xor $(OBJ)/hex_to_base64.o decrypt_single_char_xor.c

decrypt_single_char_xor.o: output_dirs decrypt_single_char_xor.c
	$(CC) -o $(OBJ)/decrypt_single_char_xor.o -c decrypt_single_char_xor.c

repeating_key_xor_test: output_dirs decrypt_single_char_xor.o base64.o repeating_key_xor.c
	$(CC) -DTEST_REPEATING_KEY_XOR -o $(BIN)/repeating_key_xor $(OBJ)/hex_to_base64.o $(OBJ)/decrypt_single_char_xor.o repeating_key_xor.c

xor_buffers_test: output_dirs xor_buffers.c
	$(CC) -DXOR_BUFFER_TEST -o $(BIN)/xor_buffers xor_buffers.c

clean:
	rm -rf $(BIN); rm -rf $(OBJ)
