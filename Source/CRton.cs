using BlossomLib.Modules.Security;
using System;
using System.IO;

namespace SexyCryptor
{
/// <summary> Initializes functions for C-RTON files from PvZ 2 (Chinese Version). </summary>

public static class CRton
{
/// <summary> The Header of an encrypted RTON File. </summary>

private const ushort MAGIC = 0x10;

/// <summary> The Block Size used. </summary>

private const RijndaelBlockSize BLOCK_SIZE = RijndaelBlockSize.SIZE_24;

/// <summary> Gets the Key used. </summary>

private static readonly byte[] KEY = GetKey();

/// <summary> Gets a IV from the given Cipher Key. </summary>

private static readonly byte[] IV = CryptoParams.InitVector(KEY, 24, 4);

// Hash Key with MD5 and get Bytes from str as ASCII

private static byte[] GetKey()
{
ReadOnlySpan<byte> rawKey = "com_popcap_pvz2_magento_product_2013_05_05"u8;

using var mOwner = GenericDigest.GetString(rawKey, "MD5");

return BinaryHelper.GetBytes(mOwner.AsSpan(), EncodingType.UTF8);
}

// Get Crypto Stream

public static void EncryptStream(Stream input, Stream output)
{
long inputLen = input.Length;

string fileSize = SizeT.FormatSize(inputLen);
TraceLogger.WriteActionStart($"Reading input data... ({fileSize})");

using NativeMemoryOwner<byte> iOwner = new(inputLen);
var inputBytes = iOwner.AsSpan();

input.ReadExactly(inputBytes);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Encrypting data...");	

using var encOwner = RijndaelCryptor.CipherData(inputBytes, KEY, true, IV, BLOCK_SIZE);
var encryptedData = encOwner.AsSpan();

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting header...");
output.WriteUInt16(MAGIC);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting encrypted data...");
output.Write(encryptedData);

TraceLogger.WriteActionEnd();
}	

/** <summary> Encrypts a RTON File by using Rijndael Ciphering. </summary>

<param name = "inputPath"> The Path where the File to be Encrypted is Located. </param>
<param name = "outputPath"> The Location where the Encrypted File will be Saved. </param> */

public static void EncryptFile(string inputPath, string outputPath)
{
TraceLogger.Init();
TraceLogger.WriteLine("Rton Encryption Started");

try
{
TraceLogger.WriteDebug($"{inputPath} --> {outputPath}");

TraceLogger.WriteActionStart("Opening files...");

using FileStream inFile = FileManager.OpenRead(inputPath);
using FileStream outFile = FileManager.OpenWrite(outputPath);

TraceLogger.WriteActionEnd();

EncryptStream(inFile, outFile);
}

catch(Exception error)
{
TraceLogger.WriteError(error, "Failed to Encrypt file");
}

TraceLogger.WriteLine("Rton Encryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

// Get Plain Stream

public static void DecryptStream(Stream input, Stream output)
{
TraceLogger.WriteActionStart("Reading header...");

ushort inputMagic = input.ReadUInt16();

if(inputMagic != MAGIC)
{
const string ERROR_INVALID_MAGIC = "Invalid CRton Identifier: {0:X4}, expected: {1:X4}";

TraceLogger.WriteError(string.Format(ERROR_INVALID_MAGIC, inputMagic, MAGIC) );
return;
}

TraceLogger.WriteActionEnd();

long inputLen = input.Length - 2;
string fileSize = SizeT.FormatSize(inputLen);

TraceLogger.WriteActionStart($"Reading encrypted data... ({fileSize})");

using NativeMemoryOwner<byte> iOwner = new(inputLen);
var inputBytes = iOwner.AsSpan();

input.ReadExactly(inputBytes);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Decrypting data...");

using var decOwner = RijndaelCryptor.CipherData(inputBytes, KEY, false, IV, BLOCK_SIZE);
var decryptedData = decOwner.AsSpan();

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting output data...");
output.Write(decryptedData);

TraceLogger.WriteActionEnd();
}

/** <summary> Decrypts a RTON File by using Rijndael Ciphering. </summary>

<param name = "inputPath"> The Path where the File to be Decrypt is Located. </param>
<param name = "outputPath"> The Path where the Decrypt File will be Saved. </param> */

public static void DecryptFile(string inputPath, string outputPath)
{
TraceLogger.Init();
TraceLogger.WriteLine("Rton Decryption Started");

try
{
TraceLogger.WriteDebug($"{inputPath} --> {outputPath}");

TraceLogger.WriteActionStart("Opening files...");

using FileStream inFile = FileManager.OpenRead(inputPath);
using FileStream outFile = FileManager.OpenWrite(outputPath);

TraceLogger.WriteActionEnd();

DecryptStream(inFile, outFile);
}

catch(Exception error)
{
TraceLogger.WriteError(error, "Failed to Decrypt file");
}

TraceLogger.WriteLine("Rton Decryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

}

}