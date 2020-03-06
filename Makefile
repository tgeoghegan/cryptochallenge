CC=xcrun -sdk macosx clang -g -Wall
BIN=bin
OBJ=obj

all: tests

output_dirs:
	mkdir -p $(BIN); mkdir -p $(OBJ)

tests: base64_test repeating_key_xor_test decrypt_single_char_xor_test xor_buffers_test 	\
	aes_128_ecb_test pkcs7_padding_test aes_cbc_test aes_ecb_cbc_oracle_test kv_parse_test  \
	ecb_cut_and_paste_test cbc_bitflip_attack_test cbc_padding_oracle_test aes_ctr_test

base64_test: output_dirs utility.o hex_to_base64.c
	$(CC) -DBASE64_TEST -o $(BIN)/hex_to_base64 $(OBJ)/utility.o hex_to_base64.c
	$(BIN)/hex_to_base64 

base64.o: output_dirs hex_to_base64.c
	$(CC) -o $(OBJ)/hex_to_base64.o -c hex_to_base64.c

decrypt_single_char_xor_test: output_dirs base64.o utility.o decrypt_single_char_xor.c
	$(CC) -DDECRYPT_SINGLE_CHAR_XOR_TEST -o $(BIN)/decrypt_single_char_xor $(OBJ)/hex_to_base64.o $(OBJ)/utility.o decrypt_single_char_xor.c
	$(BIN)/decrypt_single_char_xor
	$(BIN)/decrypt_single_char_xor input/input_4.txt

decrypt_single_char_xor.o: output_dirs decrypt_single_char_xor.c
	$(CC) -o $(OBJ)/decrypt_single_char_xor.o -c decrypt_single_char_xor.c

repeating_key_xor_test: output_dirs decrypt_single_char_xor.o base64.o repeating_key_xor.c utility.o
	$(CC) -DTEST_REPEATING_KEY_XOR -o $(BIN)/repeating_key_xor $(OBJ)/hex_to_base64.o $(OBJ)/decrypt_single_char_xor.o $(OBJ)/utility.o repeating_key_xor.c
	$(BIN)/repeating_key_xor input/input_6.txt input/decrypted_6.txt

xor_buffers.o: output_dirs xor_buffers.c
	$(CC) -o $(OBJ)/xor_buffers.o -c xor_buffers.c

xor_buffers_test: output_dirs utility.o xor_buffers.c
	$(CC) -DXOR_BUFFER_TEST -o $(BIN)/xor_buffers $(OBJ)/utility.o xor_buffers.c
	$(BIN)/xor_buffers 

aes_128_ecb.o: output_dirs aes_128_ecb.c
	$(CC) -o $(OBJ)/aes_128_ecb.o -c aes_128_ecb.c

aes_128_ecb_test: output_dirs aes_128_ecb.c utility.o base64.o
	$(CC) -DAES_128_ECB_TEST -o $(BIN)/aes_128_ecb $(OBJ)/utility.o $(OBJ)/hex_to_base64.o aes_128_ecb.c
	$(BIN)/aes_128_ecb input/input_7.txt "YELLOW SUBMARINE" input/input_8.txt

utility.o: output_dirs utility.c
	$(CC) -o $(OBJ)/utility.o -c utility.c

pkcs7_padding.o: output_dirs pkcs7_padding.c
	$(CC) -o $(OBJ)/pkcs7_padding.o -c pkcs7_padding.c

pkcs7_padding_test: output_dirs utility.o pkcs7_padding.c
	$(CC) -DPKCS7_PADDING_TEST -o $(BIN)/pkcs7_padding $(OBJ)/utility.o pkcs7_padding.c
	$(BIN)/pkcs7_padding

aes_cbc.o: output_dirs aes_cbc.c
	$(CC) -o $(OBJ)/aes_cbc.o -c aes_cbc.c

aes_cbc_test: output_dirs aes_cbc.c pkcs7_padding.o aes_128_ecb.o base64.o utility.o xor_buffers.o
	$(CC) -DAES_CBC_TEST -o $(BIN)/aes_cbc $(OBJ)/pkcs7_padding.o $(OBJ)/aes_128_ecb.o $(OBJ)/hex_to_base64.o $(OBJ)/utility.o $(OBJ)/xor_buffers.o aes_cbc.c
	$(BIN)/aes_cbc input/input_10.txt "YELLOW SUBMARINE" input/decrypted_6.txt

aes_ecb_cbc_oracle_test: output_dirs aes_ecb_cbc_oracle.c aes_cbc.o aes_128_ecb.o pkcs7_padding.o xor_buffers.o utility.o base64.o
	$(CC) -DAES_ECB_CBC_ORACLE_TEST -o $(BIN)/aes_ecb_cbc_oracle $(OBJ)/aes_cbc.o $(OBJ)/aes_128_ecb.o $(OBJ)/pkcs7_padding.o $(OBJ)/xor_buffers.o $(OBJ)/utility.o $(OBJ)/hex_to_base64.o aes_ecb_cbc_oracle.c
	$(BIN)/aes_ecb_cbc_oracle input/input_12.txt

kv_parse_test: output_dirs kv_parse.c aes_128_ecb.o pkcs7_padding.o utility.o
	$(CC) -DKV_PARSE_TEST -o $(BIN)/kv_parse $(OBJ)/aes_128_ecb.o $(OBJ)/pkcs7_padding.o $(OBJ)/utility.o kv_parse.c
	$(BIN)/kv_parse

kv_parse.o: output_dirs kv_parse.c
	$(CC) -o $(OBJ)/kv_parse.o -c kv_parse.c

ecb_cut_and_paste_test: output_dirs ecb_cut_and_paste.c kv_parse.o aes_128_ecb.o pkcs7_padding.o utility.o
	$(CC) -o $(BIN)/ecb_cut_and_paste $(OBJ)/kv_parse.o $(OBJ)/aes_128_ecb.o $(OBJ)/pkcs7_padding.o $(OBJ)/utility.o ecb_cut_and_paste.c
	$(BIN)/ecb_cut_and_paste

cbc_bitflip_attack_test: output_dirs aes_cbc.o utility.o pkcs7_padding.o kv_parse.o xor_buffers.o aes_128_ecb.o
	$(CC) -o $(BIN)/cbc_bitflip_attack $(OBJ)/kv_parse.o $(OBJ)/aes_cbc.o $(OBJ)/pkcs7_padding.o $(OBJ)/utility.o $(OBJ)/xor_buffers.o $(OBJ)/aes_128_ecb.o cbc_bitflip_attack.c
	$(BIN)/cbc_bitflip_attack

cbc_padding_oracle_test: output_dirs aes_cbc.o utility.o pkcs7_padding.o xor_buffers.o aes_128_ecb.o base64.o
	$(CC) -o $(BIN)/cbc_padding_oracle $(OBJ)/aes_cbc.o $(OBJ)/pkcs7_padding.o $(OBJ)/utility.o $(OBJ)/xor_buffers.o $(OBJ)/aes_128_ecb.o $(OBJ)/hex_to_base64.o cbc_padding_oracle.c
	$(BIN)/cbc_padding_oracle

aes_ctr.o: output_dirs aes_ctr.o
	$(CC) -o $(OBJ)/aes_ctr.o aes_ctr.c

aes_ctr_test: output_dirs utility.o xor_buffers.o aes_128_ecb.o hex_to_base64.o aes_ctr.c
	$(CC) -DAES_CTR_TEST -o $(BIN)/aes_ctr $(OBJ)/utility.o $(OBJ)/aes_128_ecb.o $(OBJ)/xor_buffers.o $(OBJ)/hex_to_base64.o aes_ctr.c
	$(BIN)/aes_ctr

clean:
	rm -rf $(BIN); rm -rf $(OBJ)
