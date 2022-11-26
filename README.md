# Info
encrypt decrypt file using of aes 256bit

# compile 
```
g++ aes.cpp -o aes -lssl -lcrypto -std=c++17
```

# Encryption File

```
./aes test.txt test.txt.enc -e
```

# Decryption File

```
./aes test.txt.enc test.txt.dec -d
```
