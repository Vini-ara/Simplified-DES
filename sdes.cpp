#include <iostream>
#include <stdint.h>
#include <vector>

#define INITIAL_PERMUTATION 0
#define P10_PERMUTATION 1
#define P8_PERMUTATION 2
#define P4_PERMUTATION 3
#define INVERSE_INITIAL_PERMUTATION 4
#define EXPANSION_PERMUTATION 5

#define NO_DEBUG false

uint8_t S0[4][4] = {
  {1, 0, 3, 2},
  {3, 2, 1, 0},
  {0, 2, 1, 3},
  {3, 1, 3, 2}
};

uint8_t S1[4][4] = {
  {0, 1, 2, 3},
  {2, 0, 1, 3},
  {3, 0, 1, 0},
  {2, 1, 0, 3}
};

void print_bits(uint16_t num, int bits) {
  for (int i = bits; i >= 0; i--) {
    std::cout << ((num >> i) & 1) << " ";
  }
  std::cout << std::endl;
}

class SDES {
  private:
    /*
     * Permutation tables
     * 
     * @param input: The input to be permuted
     * @param permutation_type: The type of permutation to be applied
     *
     * Returns the permuted output
     */
    uint16_t permutation(uint16_t input, int permutation_type) {
      input = input & 0x3FF;
                         
      uint8_t inputBits[10];
      for (int i = 0; i < 10; i++) {
        inputBits[i] = (input >> (9 - i)) & 1;
      }

      uint16_t permuted_output = 0;

      if (permutation_type == P10_PERMUTATION) {
        permuted_output = inputBits[2] << 9 |
          inputBits[4] << 8 |
          inputBits[1] << 7 |
          inputBits[6] << 6 |
          inputBits[3] << 5 |
          inputBits[9] << 4 |
          inputBits[0] << 3 |
          inputBits[8] << 2 |
          inputBits[7] << 1 |
          inputBits[5];
      } else if (permutation_type == P8_PERMUTATION) {
        permuted_output = inputBits[5] << 7 |
          inputBits[2] << 6 |
          inputBits[6] << 5 |
          inputBits[3] << 4 |
          inputBits[7] << 3 |
          inputBits[4] << 2 |
          inputBits[9] << 1 |
          inputBits[8];
      } else if (permutation_type == P4_PERMUTATION) {
        permuted_output = inputBits[7] << 3 |
          inputBits[9] << 2 |
          inputBits[8] << 1 |
          inputBits[6];
      } else if (permutation_type == INVERSE_INITIAL_PERMUTATION) {
        permuted_output = inputBits[5] << 7 |
          inputBits[2] << 6 |
          inputBits[4] << 5 |
          inputBits[6] << 4 |
          inputBits[8] << 3 |
          inputBits[3] << 2 |
          inputBits[9] << 1 |
          inputBits[7];
      } else if (permutation_type == INITIAL_PERMUTATION) {
        permuted_output = inputBits[3] << 7 | 
          inputBits[7] << 6 | 
          inputBits[4] << 5 | 
          inputBits[2] << 4 | 
          inputBits[5] << 3 | 
          inputBits[9] << 2 | 
          inputBits[6] << 1 | 
          inputBits[8];
      } else if (permutation_type == EXPANSION_PERMUTATION) {
        permuted_output = inputBits[9] << 7 | 
          inputBits[6] << 6 |
          inputBits[7] << 5 |
          inputBits[8] << 4 |
          inputBits[7] << 3 |
          inputBits[8] << 2 |
          inputBits[9] << 1 |
          inputBits[6];
      }

      return permuted_output;
    }

    /*
     * Left shift function
     *
     * @param input: The input to be shifted
     * @param shift_count: The number of bits to shift
     *
     * Returns the shifted output
     */
    uint8_t left_shift_5bit(uint8_t input, uint8_t shift_count) {
      return ((input << shift_count) | (input >> (5 - shift_count))) & 0x1F;
    }

    /*
     * Key generation function
     *
     * @param key: The 10-bit key to be used for encryption
     * 
     * Returns a vector containing the two keys (k1 and k2) generated from the input key
     */
    std::vector<uint8_t> key_generation(uint16_t key, bool debug = true) {
      key = key & 0x3FF;
      
      uint16_t permuted_key = permutation(key, P10_PERMUTATION);

      if (debug) {
        std::cout << "first key permutation: ";
        print_bits(permuted_key, 9);
      }
      
      uint8_t keys[2];
      
      keys[0] = (permuted_key >> 5) & 0x1F;

      if (debug) {
        std::cout << "left half: ";
        print_bits(keys[0], 4);
      }

      keys[1] = permuted_key & 0x1F;

      if (debug) {
        std::cout << "right half: ";
        print_bits(keys[1], 4);
      }
                                    
      keys[0] = left_shift_5bit(keys[0], 1);
      
      if (debug) {
        std::cout << "left half after shift: ";
        print_bits(keys[0], 4);
      }

      keys[1] = left_shift_5bit(keys[1], 1);

      if (debug) {
        std::cout << "right half after shift: ";
        print_bits(keys[1], 4);
      }

      uint8_t k1 = permutation((uint16_t) (keys[0] << 5) | keys[1], P8_PERMUTATION);

      if (debug) {
        std::cout << "k1: ";
        print_bits(k1, 7);
      }

      keys[0] = left_shift_5bit(keys[0], 2);

      if (debug) {
        std::cout << "left half after shift: ";
        print_bits(keys[0], 4);
      }

      keys[1] = left_shift_5bit(keys[1], 2);
      
      if (debug) {
        std::cout << "right half after shift: ";
        print_bits(keys[1], 4);
      }

      uint8_t k2 = permutation((uint16_t) (keys[0] << 5) | keys[1], P8_PERMUTATION);

      if (debug) {
        std::cout << "k2: ";
        print_bits(k1, 7);
        std::cout << "Key 1: ";
        print_bits(k1, 7);
        std::cout << "Key 2: ";
        print_bits(k2, 7);
      }

      std::vector<uint8_t> output;

      output.push_back(k1);
      output.push_back(k2); 

      return output;
    }

    /*
     * The sdes round function
     *
     * @param input: The input to be processed
     * @param key: The key to be used for the round
     *
     * Returns the result of the round function
     */
    uint8_t f_k(uint8_t input, uint8_t key, bool debug = true) {
      uint8_t left_half = (input >> 4) & 0x0F;
      uint8_t right_half = input & 0x0F;

      if (debug) {
        std::cout << "left half: ";
        print_bits(left_half, 3);
        std::cout << "right half: ";
        print_bits(right_half, 3);
      }

      uint8_t expanded_right_half = permutation(right_half, EXPANSION_PERMUTATION);

      if (debug) {
        std::cout << "expanded right half: ";
        print_bits(expanded_right_half, 7);
      }

      uint8_t xor_result = expanded_right_half ^ key;

      if (debug) {
        std::cout << "xor result: ";
        print_bits(xor_result, 7);
      }

      uint8_t xor_left_half = (xor_result >> 4) & 0x0F;
      uint8_t xor_right_half = xor_result & 0x0F; 

      uint8_t row_left = ((xor_left_half & 0x08) >> 2) | (xor_left_half & 0x01);
      uint8_t row_right = ((xor_right_half & 0x08) >> 2) | (xor_right_half & 0x01);

      if (debug) {
        std::cout << "row left: ";
        print_bits(row_left, 1);
        std::cout << "row right: ";
        print_bits(row_right, 1);
      }

      uint8_t col_left = (xor_left_half & 0x06) >> 1;
      uint8_t col_right = (xor_right_half & 0x06) >> 1;
      
      if (debug) {
        std::cout << "col left: ";
        print_bits(col_left, 1);
        std::cout << "col right: ";
        print_bits(col_right, 1);
      }


      uint8_t sbox_left = S0[row_left][col_left];
      uint8_t sbox_right = S1[row_right][col_right];

      if (debug) {
        std::cout << "sbox left: ";
        print_bits(sbox_left, 1);
        std::cout << "sbox right: ";
        print_bits(sbox_right, 1);
      }

      uint8_t sbox_result = (sbox_left << 2) | sbox_right;

      if (debug) {
        std::cout << "sbox result: ";
        print_bits(sbox_result, 3);
      }

      uint8_t permuted_result = permutation(sbox_result, P4_PERMUTATION);

      if (debug) {
        std::cout << "permuted result: ";
        print_bits(permuted_result, 3);
      }

      uint8_t final_result = (left_half ^ permuted_result) << 4 | right_half;

      if (debug) {
        std::cout << "final result: ";
        print_bits(final_result, 7);
      }

      return final_result;
    }

  public: 
    /*
     * Simplified-DES encryption function
     *
     * @param input: The input byte to be encrypted
     * @param key: The 10-bit key to be used for encryption
     *
     * Returns the encrypted byte
     */
    uint8_t sdes_encrypt(uint8_t input, uint16_t key, bool debug = true) {
      auto keys = key_generation(key, debug);

      if (debug) {
        std::cout << "Encrypting..." << std::endl;
        std::cout << "Input: ";
        print_bits(input, 7);
      }

      uint8_t permuted_input = permutation(input, INITIAL_PERMUTATION);

      if (debug) {
        std::cout << "initial perm: ";
        print_bits(permuted_input, 7);
      }

      uint8_t result = f_k(permuted_input, keys[0], debug);

      if (debug) {
        std::cout << "f_k 1: ";
        print_bits(result, 7);
      }

      result = (result & 0x0F) << 4 | (result >> 4);

      if (debug) {
        std::cout << "swap: ";
        print_bits(result, 7);
      }

      result = f_k(result, keys[1], debug);

      if (debug) {
        std::cout << "f_k 2: ";
        print_bits(result, 7);
      }

      result = permutation(result, INVERSE_INITIAL_PERMUTATION);
      
      if (debug) {
        std::cout << "result perm: ";
        print_bits(result, 7);
      }

      return result;
    }

    /*
     * Simplified-DES decryption function
     *
     * @param input: The input byte to be decrypted
     * @param key: The 10-bit key to be used for decryption
     *
     * Returns the decrypted byte
     */
    uint8_t sdes_decrypt(uint8_t input, uint16_t key, bool debug = true) {
      auto keys = key_generation(key, debug);

      if (debug) {
        std::cout << "Decrypting..." << std::endl;
        std::cout << "Input: ";
        print_bits(input, 7);
      }

      uint8_t permuted_input = permutation(input, INITIAL_PERMUTATION);

      if (debug) {
        std::cout << "initial perm: ";
        print_bits(permuted_input, 7);
      }

      uint8_t result = f_k(permuted_input, keys[1], debug);
                                                     
      if (debug) {
        std::cout << "f_k 1: ";
        print_bits(result, 7);
      }

      result = (result & 0x0F) << 4 | (result >> 4);

      if (debug) {
        std::cout << "swap: ";
        print_bits(result, 7);
      }

      result = f_k(result, keys[0], debug);

      if (debug) {
        std::cout << "f_k 2: ";
        print_bits(result, 7);
      }

      result = permutation(result, INVERSE_INITIAL_PERMUTATION);

      if (debug) {
        std::cout << "result: ";
        print_bits(result, 7);
      }

      return result;
    }

    /*
     * Simplified-DES encryption function in ECB mode
     *
     * @param input: A vector of input bytes to be encrypted
     * @param key: The 10-bit key to be used for encryption
     *
     * @returns: A vector of encrypted bytes
     */
    std::vector<uint8_t> ecb_sdes_encrypt(std::vector<uint8_t> input, uint16_t key) {
      std::vector<uint8_t> output;

      for (auto byte : input) {
        output.push_back(sdes_encrypt(byte, key, NO_DEBUG));
      }

      return output;
    }

    /*
     * Simplified-DES decryption function in ECB mode
     *
     * @param input: A vector of input bytes to be decrypted
     * @param key: The 10-bit key to be used for decryption
     *
     * @returns: A vector of decrypted bytes
     */
    std::vector<uint8_t> ecb_sdes_decrypt(std::vector<uint8_t> input, uint16_t key) {
      std::vector<uint8_t> output;

      for (auto byte : input) {
        output.push_back(sdes_decrypt(byte, key, NO_DEBUG));
      }

      return output;
    }

    /*
     * Simplified-DES encryption function in CBC mode
     *
     * @param input: A vector of input bytes to be encrypted
     * @param iv: The initialization vector to be used for encryption
     * @param key: The 10-bit key to be used for encryption
     *
     * @returns: A vector of encrypted bytes
     */
    std::vector<uint8_t> cbc_sdes_encrypt(std::vector<uint8_t> input, uint8_t iv, uint16_t key) {
      std::vector<uint8_t> output;

      uint8_t previous_block = iv;

      for (auto byte : input) {
        uint8_t xor_result = byte ^ previous_block;
        uint8_t encrypted_byte = sdes_encrypt(xor_result, key, NO_DEBUG);
        output.push_back(encrypted_byte);
        previous_block = encrypted_byte;
      }

      return output;
    }

    /*
     * Simplified-DES decryption function in CBC mode
     *
     * @param input: A vector of input bytes to be decrypted
     * @param iv: The initialization vector to be used for decryption
     * @param key: The 10-bit key to be used for decryption
     *
     * @returns: A vector of decrypted bytes
     */
    std::vector<uint8_t> cbc_sdes_decrypt(std::vector<uint8_t> input, uint8_t iv, uint16_t key) {
      std::vector<uint8_t> output;

      uint8_t previous_block = iv;

      for (auto byte : input) {
        uint8_t decrypted_byte = sdes_decrypt(byte, key, NO_DEBUG);
        uint8_t xor_result = decrypted_byte ^ previous_block;
        output.push_back(xor_result);
        previous_block = byte;
      }

      return output;
    }
};

int main() {
  uint8_t plaintext = 0xD7;

  uint16_t key = 0x282;

  SDES sdes;

  std::cout << "Testing SDES Encryption..." << std::endl;
  std::cout << std::endl;

  std::cout << "Plaintext: " << std::endl;
  print_bits(plaintext, 7);
  std::cout << std::endl;
  
  std::cout << "10-bit key: " << std::endl;
  print_bits(key, 9);
  std::cout << std::endl;
  
  uint8_t encrypted = sdes.sdes_encrypt(plaintext, key);

  std::cout << std::endl;
  
  std::cout << "Encrypted: " << std::endl;
  print_bits(encrypted, 7);
  std::cout << std::endl;

  std::cout << "Testing SDES decription..." << std::endl;
  
  uint8_t decrypted = sdes.sdes_decrypt(encrypted, key);

  std::cout << std::endl;
  
  std::cout << "Decrypted: " << std::endl;
  print_bits(decrypted, 7);
  std::cout << std::endl;

  // ------------------------------- ECB TESTING -------------------------------

  std::cout << "Testing ECB mode..." << std::endl;
  std::cout << std::endl;

  std::vector<uint8_t> plaintext_ecb = {0xD7, 0x6C, 0xBA, 0xF0};

  std::cout << "Plaintext: " << std::endl;
  for (auto byte : plaintext_ecb) {
    print_bits(byte, 7);
  }
  std::cout << std::endl;

  uint16_t key_ecb = 0x282;

  std::cout << "10-bit key: " << std::endl;
  print_bits(key_ecb, 9);
  std::cout << std::endl;

  std::vector<uint8_t> encrypted_ecb = sdes.ecb_sdes_encrypt(plaintext_ecb, key_ecb);

  std::cout << "Encrypted: " << std::endl;
  for (auto byte : encrypted_ecb) {
    print_bits(byte, 7);
  }
  std::cout << std::endl;

  std::vector<uint8_t> decrypted_ecb = sdes.ecb_sdes_decrypt(encrypted_ecb, key_ecb);

  std::cout << "Decrypted: " << std::endl;
  for (auto byte : decrypted_ecb) {
    print_bits(byte, 7);
  }
  std::cout << std::endl;


  // ------------------------------- CBC TESTING -------------------------------

  std::cout << "Testing CBC mode..." << std::endl;
  std::cout << std::endl;

  std::vector<uint8_t> plaintext_cbc = {0xD7, 0x6C, 0xBA, 0xF0};

  std::cout << "Plaintext: " << std::endl;
  for (auto byte : plaintext_cbc) {
    print_bits(byte, 7);
  }
  std::cout << std::endl;

  uint8_t iv = 0x55;

  std::cout << "IV: " << std::endl;
  print_bits(iv, 7);
  std::cout << std::endl;

  uint16_t key_cbc = 0x282;

  std::cout << "10-bit key: " << std::endl;
  print_bits(key_cbc, 9);
  std::cout << std::endl;

  std::vector<uint8_t> encrypted_cbc = sdes.cbc_sdes_encrypt(plaintext_cbc, iv, key_cbc);

  std::cout << "Encrypted: " << std::endl;
  for (auto byte : encrypted_cbc) {
    print_bits(byte, 7);
  }
  std::cout << std::endl;

  std::vector<uint8_t> decrypted_cbc = sdes.cbc_sdes_decrypt(encrypted_cbc, iv, key_cbc);

  std::cout << "Decrypted: " << std::endl;
  for (auto byte : decrypted_cbc) {
    print_bits(byte, 7);
  }
  std::cout << std::endl;
  
  return 0;
}
