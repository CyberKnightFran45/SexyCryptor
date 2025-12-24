using System;
using System.IO;
using BlossomLib.Modules.Security;

namespace SexyCryptor
{
/** <summary> Allows Encrypting or Decrypting TalkWeb Files by using DES + Hex </summary>

<remarks> Used in: <c>twpay.xml</c> file from Apk assets (PvZ 2 China) and
<c>Account</c> request for Login </remarks> */

public static class TWSecurity
{
/// <summary> The Key used. </summary>

private static readonly byte[] KEY = "TwPay001"u8.ToArray();

/// <summary> The IV used. </summary>

private static readonly byte[] IV = [ 1, 2, 3, 4, 5, 6, 7, 8 ];

// Check Encrypted String

public static bool IsValidHex(ReadOnlySpan<char> str)
{

if(str.Length % 16 != 0)
return false;

foreach(char c in str)
{
bool isDigit = c >= '0' && c <= '9';
bool isUpperHex = c >= 'A' && c <= 'F';

if(!isDigit && !isUpperHex)
return false;

}

return true;
}

// Encrypt Raw Bytes 

private static NativeMemoryOwner<char> Encrypt(byte[] data) => XDes.Encrypt(data, KEY, IV);

// Encrypt Json String

private static string EncryptJson(ReadOnlySpan<char> data)
{
var rawBytes = BinaryHelper.GetBytes(data, EncodingType.UTF8);
using var xOwner = Encrypt(rawBytes);

return new(xOwner.AsSpan() );
}

// Get Crypto Stream

public static void EncryptStream(Stream input, Stream output)
{
long inputLen = input.Length;

string fileSize = SizeT.FormatSize(inputLen);
TraceLogger.WriteActionStart($"Reading input data... ({fileSize})");

var inputBytes = new byte[inputLen];
input.ReadExactly(inputBytes);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Encrypting data...");	
using var xOwner = Encrypt(inputBytes);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting encrypted data...");
output.WriteString(xOwner.AsSpan() );

TraceLogger.WriteActionEnd();
}	

/** <summary> Encrypts TW file by using DES Ciphering. </summary>

<param name = "inputPath"> The Path where the File to be Encrypted is Located. </param>
<param name = "outputPath"> The Location where the Encrypted File will be Saved. </param> */

public static void EncryptFile(string inputPath, string outputPath)
{
TraceLogger.Init();
TraceLogger.WriteLine("TW Encryption Started");

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

TraceLogger.WriteLine("TW Encryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

// Decrypt Hex Data as Raw Bytes

private static byte[] Decrypt(ReadOnlySpan<char> data)
{
int junkIndex = data.IndexOf('-');

if(junkIndex != -1)
data = data[..junkIndex]; // Ignore Base64 Junk

return XDes.Decrypt(data, KEY, IV);
}

// Decrypt Hex Data as Json

private static string DecryptJson(ReadOnlySpan<char> data)
{
var rawData = Decrypt(data);

return BinaryHelper.GetString(rawData, EncodingType.UTF8);
}

// Get Plain Stream

public static void DecryptStream(Stream input, Stream output)
{
long inputLen = input.Length;
string fileSize = SizeT.FormatSize(inputLen);

TraceLogger.WriteActionStart($"Reading encrypted data... ({fileSize})");
using var iOwner = input.ReadString(inputLen);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Decrypting data...");
var decryptedData = Decrypt(iOwner.AsSpan() );

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting output data...");
output.Write(decryptedData);

TraceLogger.WriteActionEnd();
}

/** <summary> Decrypts PayConfig file by using DES Ciphering. </summary>

<param name = "inputPath"> The Path where the File Ecrypted is Located. </param>
<param name = "outputPath"> The Location where the Decrypted File will be Saved. </param> */

public static void DecryptFile(string inputPath, string outputPath)
{
TraceLogger.Init();
TraceLogger.WriteLine("TW Decryption Started");

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

TraceLogger.WriteLine("TW Decryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

/** <summary> Ciphers the providen Data with DES (CBC Mode), then convert it with HEX. </summary>

<param name="data"> Data to cipher (represented as a String) </param>
<param name="forEncryption"> Encryption mode </param>

<returns> A string containing the data ciphered </returns> */

public static string CipherData(ReadOnlySpan<char> data, bool forEncryption)
{
return forEncryption ? EncryptJson(data) : DecryptJson(data);
}

}

}