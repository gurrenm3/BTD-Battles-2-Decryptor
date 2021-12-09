/// <summary>
/// A class for dealing with files that use NinjaKiwi's Bin2.0 encryption.
/// <br/>Thanks to Vadmeme for creating the original implementation of this. 
/// Their github can be found here: https://github.com/Vadmeme
/// </summary>
public static class BinEncryption
{
    /// <summary>
    /// The header that identifies this file as being encrypted with Bin2.0.
    /// </summary>
    const string header = "%BIN_2.0";

    /// <summary>
    /// The byte equivalent of <see cref="header"/>.
    /// </summary>
    static byte[] headerBytes;

    static BinEncryption()
    {
        headerBytes = Encoding.UTF8.GetBytes(header);
    }


    /// <summary>
    /// Reads the text from a file and decrypts it, returning a new string with the unencrypted text.
    /// If the text doesn't start with <see cref="header"/> it is assumed it's already decrypted and it will be returned.
    /// </summary>
    /// <param name="filePath">The path of the file you want to decrypt.</param>
    /// <param name="saveDecryptedText">Whether or not the file should be overwritten with the decrypted text.</param>
    /// <returns>The decrypted text from this file.</returns>
    public static string DecryptFile(string filePath, bool saveDecryptedText = false)
    {
        // Perform checks to make sure file is good.
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            return null;

        // This file doesn't have a BIN2.0 header. Assuming it's already been decrypted.
        if (!HasBinHeader(filePath))
            return Encoding.UTF8.GetString(File.ReadAllBytes(filePath));

        var textBytes = DecryptBytesInternal(File.ReadAllBytes(filePath));

        var byteArray = textBytes.ToArray();
        if (saveDecryptedText)
            File.WriteAllBytes(filePath, byteArray);

        return Encoding.UTF8.GetString(byteArray);
    }

    /// <summary>
    /// Reads the contents of a <see cref="ZipArchiveEntry"/> and decrypts it, returning a new string of the unencrypted text.
    /// <br/>If the content's bytes don't start with <see cref="header"/> it is assumed it's already decrypted and therefore will
    /// be returned without attempting to decrypt them.
    /// </summary>
    /// <param name="entry">The <see cref="ZipArchiveEntry"/> to be decrypted.</param>
    /// <param name="saveDecryptedText">Whether or not the file should be overwritten with the decrypted text.</param>
    /// <returns>The decrypted text from this file.</returns>
    public static string DecryptFile(ZipArchiveEntry entry, bool saveDecryptedText = false)
    {
        if (entry == null)
            return null;

        // This entry doesn't have a BIN2.0 header. Assuming it's already been decrypted.
        if (!IsEncrypted(entry))
        {
            using var sr = new StreamReader(entry.Open());
            string text = sr.ReadToEnd();
            sr.Close();
            return text;
        }

        var stream = entry.Open();
        Span<byte> textBytes = new Span<byte>(new byte[stream.Length]);
        stream.Read(textBytes);

        textBytes = DecryptBytesInternal(textBytes);
        string decryptedText = Encoding.UTF8.GetString(textBytes);

        if (saveDecryptedText)
        {
            using var sw = new StreamWriter(stream);
            sw.BaseStream.SetLength(0);
            sw.BaseStream.SetLength(decryptedText.Length);
            sw.Write(decryptedText);
            sw.Close();
            entry.LastWriteTime = DateTimeOffset.UtcNow.LocalDateTime;
        }

        stream.Close();
        return decryptedText;
    }

    /// <summary>
    /// Internal method for decrypting bytes. This has been separated from other methods for reusability.
    /// </summary>
    /// <param name="textBytes">Encrypted text bytes.</param>
    /// <returns>Unencrypted text bytes.</returns>
    private static Span<byte> DecryptBytesInternal(Span<byte> textBytes)
    {
        // Get key based on text length. Removing header length because it's not apart of the encrypted text.
        var keyBytes = GetKeyBytes(textBytes.Length - header.Length);

        // Move the last 8 bytes to the front, overwriting the header. We're moving 8 because that's how long the header is.
        for (int i = 0; i < header.Length; i++)
            textBytes[i] = textBytes[textBytes.Length - (header.Length - i)];


        // Removing the bytes at the end because we just copied them to the front.
        textBytes = textBytes.Slice(0, textBytes.Length - header.Length);


        // Performing XOR Bitwise operation. This is what actually decrypts the text based on the key.
        for (int i = 0; i < textBytes.Length; i++)
            textBytes[i] ^= keyBytes[i % keyBytes.Count];

        return textBytes;
    }


    /// <summary>
    /// Encrypt the contents of a file, making them have the Bin2.0 encryption. 
    /// This will overwrite the original contents of the file.
    /// </summary>
    /// <param name="filePath">Location of the file whose contents will be encrypted.</param>
    /// <returns>True if the file was successfully encrypted. False if it failed to encrypt or was already encrypted.</returns>
    public static bool EncryptFile(string filePath)
    {
        if (IsEncrypted(filePath))
            return false;

        var textBytes = EncryptBytesInternal(File.ReadAllBytes(filePath).ToList());
        File.WriteAllBytes(filePath, textBytes.ToArray());
        return true;
    }

    /// <summary>
    /// Encrypt the contents of a <see cref="ZipArchiveEntry"/>, making them have the Bin2.0 encryption. 
    /// This will overwrite the original contents of the file.
    /// </summary>
    /// <param name="entry">The zip entry that will be encrypted.</param>
    /// <returns>True if the file was successfully encrypted. False if it failed to encrypt or was already encrypted.</returns>
    public static bool EncryptFile(ZipArchiveEntry entry)
    {
        if (IsEncrypted(entry))
            return false;

        var stream = entry.Open();
        var spanBytes = new byte[stream.Length];
        stream.Read(spanBytes);

        List<byte> textBytes = new List<byte>();
        textBytes.AddRange(spanBytes);
        textBytes = EncryptBytesInternal(textBytes);

        stream.SetLength(0);
        stream.SetLength(textBytes.Count);
        stream.Write(textBytes.ToArray());
        stream.Close();
        entry.LastWriteTime = DateTimeOffset.UtcNow.LocalDateTime;
        return true;
    }


    /// <summary>
    /// Internal method for encrypting bytes. This has been separated from other methods for reusability.
    /// </summary>
    /// <param name="textBytes"></param>
    private static List<byte> EncryptBytesInternal(List<byte> textBytes)
    {
        var keyBytes = GetKeyBytes(textBytes.Count);

        // Performing XOR Bitwise operation. This is what actually encrypts the text based on the key.
        for (int i = 0; i < textBytes.Count; i++)
            textBytes[i] ^= keyBytes[i % keyBytes.Count];

        // Move first bytes back to the end. Decrypting moves last bytes to the front so we're just reversing it.
        for (int i = 0; i < header.Length; i++)
        {
            textBytes.Insert(textBytes.Count, textBytes[0]);
            textBytes.RemoveAt(0);
        }

        // Reinsert encryption header at front.
        textBytes.InsertRange(0, headerBytes);
        return textBytes;
    }



    /// <summary>
    /// Checks a <see cref="ZipArchiveEntry"/>'s contents and determines if they are encrypted with the Bin2.0 encryption.
    /// </summary>
    /// <param name="entry">The entry whose contents will be checked.</param>
    /// <returns>Will return true if the contents are encrypted with Bin2.0 encryption, otherwise will return false.</returns>
    public static bool IsEncrypted(ZipArchiveEntry entry)
    {
        if (entry == null)
            throw new Exception("Couldn't encrypt Entry because it was null");

        if (entry.Archive.Mode != ZipArchiveMode.Update)
            throw new Exception("Unable to read zip entry because the Zip Archive was opened incorrectly." +
                $" Please reopen the Zip Archive with \"{nameof(ZipArchiveMode)}.{nameof(ZipArchiveMode.Update)}\"");

        return HasBinHeader(entry);
    }

    /// <summary>
    /// Checks a file's contents and determines if they are encrypted with the Bin2.0 encryption.
    /// </summary>
    /// <param name="filePath">Path to the file whose content's will be checked.</param>
    /// <returns>Will return true if the contents are encrypted with Bin2.0 encryption, otherwise will return false.</returns>
    public static bool IsEncrypted(string filePath)
    {
        if (string.IsNullOrEmpty(filePath) || !File.Exists(filePath))
            throw new Exception("Unable to read file's contents because no file exists at the path provided");

        return HasBinHeader(filePath);
    }


    /// <summary>
    /// Returns whether or not a file's bytes start with the bytes for <see cref="header"/>.
    /// <br/>If it does then it means the file's contents have been encrypted using Bin2.0.
    /// </summary>
    /// <param name="filePath">The full path to the file to check.</param>
    /// <returns>Will return true if the file's initial bytes are the same as <see cref="header"/>, otherwise will return false.</returns>
    private static bool HasBinHeader(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open);
        if (fs.Length < header.Length)
            return false;

        for (int i = 0; i < header.Length; i++)
            if (fs.ReadByte() != headerBytes[i])
                return false;

        return true;
    }

    /// <summary>
    /// Returns whether or not a <see cref="ZipArchiveEntry"/>'s bytes start with the bytes for <see cref="header"/>.
    /// <br/>If it does then it means the entry's contents have been encrypted using Bin2.0.
    /// </summary>
    /// <param name="entry">The entry to check.</param>
    /// <returns>Will return true if the entry's initial bytes are the same as <see cref="header"/>, otherwise will return false.</returns>
    private static bool HasBinHeader(ZipArchiveEntry entry)
    {
        var stream = entry.Open();
        if (stream.Length < header.Length)
        {
            stream.Close();
            return false;
        }

        for (int i = 0; i < header.Length; i++)
        {
            if (stream.ReadByte() != headerBytes[i])
            {
                stream.Close();
                return false;
            }
        }

        stream.Close();
        return true;
    }


    /// <summary>
    /// Calculates the encrypt/decrypt key for the provided text.
    /// </summary>
    /// <param name="textLength">Get's the unique encrypt/decrypt key for text of this length.</param>
    private static uint[] GetKey(int textLength)
    {
        uint textSize = (uint)textLength; // converting to uint. It must be uint in order to properly get the key.

        var keyOut = new uint[4];
        uint key_chunk_a = (32 * (((textSize ^ (textSize << 13)) >> 17) ^ textSize ^ (textSize << 13))) ^ ((textSize ^ (textSize << 13)) >> 17) ^ textSize ^ (textSize << 13);
        uint key_chunk_b = (((key_chunk_a << 13) ^ key_chunk_a) >> 17) ^ (key_chunk_a << 13) ^ key_chunk_a;
        uint key_chunk_c = (32 * key_chunk_b) ^ key_chunk_b;
        uint key_chunk_d = (((key_chunk_c << 13) ^ key_chunk_c) >> 17) ^ (key_chunk_c << 13) ^ key_chunk_c;
        uint key_chunk_e = (32 * key_chunk_d) ^ key_chunk_d;
        uint key_chunk_f = (((key_chunk_e << 13) ^ key_chunk_e) >> 17) ^ (key_chunk_e << 13) ^ key_chunk_e;
        uint key_chunk_g = key_chunk_f ^ (32 * key_chunk_f);

        keyOut[0] = key_chunk_a;
        keyOut[1] = key_chunk_c;
        keyOut[2] = key_chunk_e;
        keyOut[3] = key_chunk_g;

        return keyOut;
    }

    /// <summary>
    /// Get's the encryption key based on text length and returns it in byte form.
    /// </summary>
    /// <param name="textLength">Length of the text you want the encryption key for.</param>
    /// <returns></returns>
    private static List<byte> GetKeyBytes(int textLength)
    {
        var key = GetKey(textLength);
        List<byte> keyBytes = new List<byte>();
        for (int i = 0; i < key.Length; i++)
        {
            keyBytes.AddRange(BitConverter.GetBytes(key[i]));
        }
        return keyBytes;
    }
}
