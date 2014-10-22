CC=xcrun -sdk macosx clang
BIN=bin
OBJ=obj

output_dirs:
	mkdir -p $(BIN); mkdir -p $(OBJ)

all: tests

tests: base64_test repeating_key_xor_test decrypt_single_char_xor_test xor_buffers_test aes_128_ecb_test pkcs7_padding_test

base64_test: output_dirs hex_to_base64.c
	$(CC) -DBASE64_TEST -o $(BIN)/hex_to_base64 hex_to_base64.c
	$(BIN)/hex_to_base64 

base64.o: output_dirs hex_to_base64.c
	$(CC) -o $(OBJ)/hex_to_base64.o -c hex_to_base64.c

decrypt_single_char_xor_test: output_dirs base64.o decrypt_single_char_xor.c
	$(CC) -DDECRYPT_SINGLE_CHAR_XOR_TEST -o $(BIN)/decrypt_single_char_xor $(OBJ)/hex_to_base64.o decrypt_single_char_xor.c

decrypt_single_char_xor.o: output_dirs decrypt_single_char_xor.c
	$(CC) -o $(OBJ)/decrypt_single_char_xor.o -c decrypt_single_char_xor.c
	$(BIN)/decrypt_single_char_xor
	$(BIN)/decrypt_single_char_xor input/input_4.txt

repeating_key_xor_test: output_dirs decrypt_single_char_xor.o base64.o repeating_key_xor.c utility.o
	$(CC) -DTEST_REPEATING_KEY_XOR -o $(BIN)/repeating_key_xor $(OBJ)/hex_to_base64.o $(OBJ)/decrypt_single_char_xor.o $(OBJ)/utility.o repeating_key_xor.c
	$(BIN)/repeating_key_xor input/input_6.txt input/decrypted_6.txt

xor_buffers_test: output_dirs xor_buffers.c
	$(CC) -DXOR_BUFFER_TEST -o $(BIN)/xor_buffers xor_buffers.c
	$(BIN)/xor_buffers 

aes_128_ecb.o:
	$(CC) -o $(BIN)/aes_128_ecb.o -c aes_128_ecb.c

aes_128_ecb_test: aes_128_ecb.c utility.o base64.o
	$(CC) -DAES_128_ECB_TEST -o $(BIN)/aes_128_ecb $(OBJ)/utility.o $(OBJ)/hex_to_base64.o aes_128_ecb.c
	$(BIN)/aes_128_ecb input/input_7.txt "YELLOW SUBMARINE" input/input_8.txt

utility.o: utility.c
	$(CC) -o $(OBJ)/utility.o -c utility.c

pkcs7_padding.o: pkcs7_padding.c
	$(CC) -o $(OBJ)/pkcs7_padding.o -c pkcs7_padding.c

pkcs7_padding_test: pkcs7_padding.c
	$(CC) -DPKCS7_PADDING_TEST -o $(BIN)/pkcs7_padding pkcs7_padding.c
	$(BIN)/pkcs7_padding

clean:
	rm -rf $(BIN); rm -rf $(OBJ)
