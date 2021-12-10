# Bloons TD Battles 2 Decryptor
An encryptor/decryptor for Ninja Kiwi's Bin2.0 encryption, which is used in Bloons TD Battles 2. This file is based off of the original C++ implementation, made by Vadmeme https://github.com/Vadmeme

Ninja Kiwi is a great game studio that makes much loved Tower Defense games. Sometimes some of their game files are encrypted to improve performance or restrict modding. One of the encryptions they've made is the Bin 2.0 encryption, which is used in Bloons TD Battles 2 to obscure the code for assets. This repo contains a single class called BinEncryption, which can be used to encrypt/decrypt any files whose contents have this encryption. This encrypt/decryptor was originally written in C++ by another modder who gave me permission to recreate it in C#. This C# version is a heavily refactored version of the original. It's been thoroughly documented with every variable/method/comment being as clear and concise as possible. It's also more modularized to increase usability and allow for more options like encrypting/decrypting zip files.

Example of decryption:
```
string filePath = "someFilePath";
string decryptedText = BinEncryption.DecryptFile(filePath);
```

Example of encryption:
```
string filePath = "someFilePath";
BinEncryption.EncryptFile(filePath);
```

Example of utility methods:
```
string filePath = "someFilePath";
if (BinEncryption.IsEncrypted(filePath))
{
    Console.WriteLine("This file is already encrypted!");
}
```

I decided to rewrite the C++ version to make a more documented version of the original that was accessible to C# programmers like me. I did not make it to help people cheat or to cause harm to Ninja Kiwi, their games, or other players. I only made to to help good modders share their passion for Ninja Kiwi and their awesome games. How you use this and the consequences you may experience from your actions are not my fault or responsibility.
