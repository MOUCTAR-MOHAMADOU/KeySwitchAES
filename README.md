# key switching AES
homomorphic of evaluation of AES based on circuit bootstrapping mode.

## Setup
Following Code is used to check sanity of the TFHEpp library, and it measures how much time homomorphic NAND takes on your machine with TFHEpp. 
```
git clone https://github.com/prajyotgupta/tfhepp
cd tfhepp
mkdir build
cd build
cmake .. -DENABLE_TEST=ON
make.

```
## Test

ka: 54 68 61 74 73 20 6D 79 20 4B 75 6E 67 20 46 75

Plaintext_Alice : 54 77 6F 20 4F 6E 65 20 4E 69 6E 65 20 54 77 6F

ciphertext_Alice: 29 C3 50 5F 57 14 20 F6 40 22 99 B3 1A 02 D7 3A

kb = 2b 7e 15 16 28 ae d2 a6 ab f7 15 88 09 cf 4f 3c

m = 32 43 f6 a8 88 5a 30 8d 31 31 98 a2 e0 37 07 34

M = 39 25 84 1d 02 dc 09 fb dc 11 85 97 19 6a 0b 32

ciphertext_Bob : d3 78 37 a2 47 90 c5 f0 80 f0 42 dc c8 a4 a1 5a

Text after kb encryption: d3 78 37 a2 47 90 c5 f0 80 f0 42 dc c8 a4 a1 5a
