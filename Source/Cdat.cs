using BlossomLib.Modules.Security;
using System;
using System.IO;

namespace SexyCryptor
{
/** <summary> Initializes functions for C-dat files from PvZ Free (Android). </summary>

<remarks> C-dat stands for <c>Ciphered Data</c>, used for Encrypting Images (png) </remarks> */

public static class Cdat
{
/// <summary> The Header of a CDAT File. </summary>

private const string HEADER = "CRYPT_RES";

/// <summary> The Identifier of a CDAT File. </summary>

private const ushort FLAGS = 0x0A;

/// <summary> The Number of Bytes to Cipher. </summary>

private const int BYTES_TO_CIPHER = 256;

/// <summary> The Key used. </summary>

private static readonly byte[] KEY = "AS23DSREPLKL335KO4439032N8345NF"u8.ToArray();

// Get CDAT Stream

public static void EncryptStream(Stream input, Stream output,
                                 Action<long, long> progressCallback = null)
{
long inputLen = input.Length;

TraceLogger.WriteActionStart("Writting header...");

output.WriteString(HEADER);
output.WriteUInt16(FLAGS);
output.WriteInt64(inputLen);

TraceLogger.WriteActionEnd();

string fileSize = SizeT.FormatSize(inputLen);
TraceLogger.WriteActionStart($"Encrypting data... ({fileSize})");

if(inputLen >= BYTES_TO_CIPHER)
XorCryptor.CipherStream(input, output, KEY, BYTES_TO_CIPHER, progressCallback);

FileManager.Process(input, output, -1, progressCallback);
TraceLogger.WriteActionEnd();
}

/** <summary> Encrypts the specified File by using XOR Ciphering. </summary>

<param name = "inputPath"> The Path where the File to be Encrypted is Located. </param>
<param name = "outputPath"> The Location where the Encrypted File will be Saved. </param> */

public static void EncryptFile(string inputPath, string outputPath,
                               Action<long, long> progressCallback = null)
{
TraceLogger.Init();
TraceLogger.WriteLine("Cdat Encryption Started");

try
{
PathHelper.ChangeExtension(ref outputPath, ".cdat");
TraceLogger.WriteDebug($"{inputPath} --> {outputPath}");

TraceLogger.WriteActionStart("Opening files...");

using FileStream inFile = FileManager.OpenRead(inputPath);
using FileStream outFile = FileManager.OpenWrite(outputPath);

TraceLogger.WriteActionEnd();

EncryptStream(inFile, outFile, progressCallback); 
}

catch(Exception error)
{
TraceLogger.WriteError(error, "Failed to Encrypt file");
}

TraceLogger.WriteLine("Cdat Encryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

// Get Plain Stream

public static void DecryptStream(Stream input, Stream output,
                                 Action<long, long> progressCallback = null)
{
TraceLogger.WriteActionStart("Reading header...");

using var hOwner = input.ReadString(HEADER.Length);
var inputHeader = hOwner.AsSpan();

if(!inputHeader.SequenceEqual(HEADER) )
{
TraceLogger.WriteError($"Invalid header: \"{inputHeader}\", expected: \"{HEADER}\"");
return;
}

ushort inputFlags = input.ReadUInt16();

if(inputFlags != FLAGS)
{
const string ERROR_INVALID_FLAGS = "Invalid Cdat Type: {0:X4}, expected: {1:X4}";

TraceLogger.WriteError(string.Format(ERROR_INVALID_FLAGS, inputFlags, FLAGS) );
return;
}

long sizeBeforeEnc = input.ReadInt64();
output.SetLength(sizeBeforeEnc);

TraceLogger.WriteActionEnd();

string fileSize = SizeT.FormatSize(sizeBeforeEnc);
TraceLogger.WriteActionStart($"Decrypting data... ({fileSize})");

int minLen = HEADER.Length + BYTES_TO_CIPHER + 10;

// Total bytes: Header(9) + Flags(2) + SizeBeforeEncryption(8) + XorData(256) = 275

if(input.Length >= minLen)
XorCryptor.CipherStream(input, output, KEY, BYTES_TO_CIPHER, progressCallback);

FileManager.Process(input, output, -1, progressCallback);
TraceLogger.WriteActionEnd();
}

/** <summary> Decrypts a CDAT File that was Encrypted with XOR Ciphering. </summary>

<param name = "inputPath"> The Path where the File to be Decrypted is Located. </param>
<param name = "outputPath"> The Location where the Decrypted File will be Saved. </param> */

public static void DecryptFile(string inputPath, string outputPath,
                               Action<long, long> progressCallback = null)
{
TraceLogger.Init();
TraceLogger.WriteLine("Cdat Decryption Started");

try
{
PathHelper.ChangeExtension(ref outputPath, ".png");
TraceLogger.WriteDebug($"{inputPath} --> {outputPath}");

TraceLogger.WriteActionStart("Opening files...");

using FileStream inFile = FileManager.OpenRead(inputPath);
using FileStream outFile = FileManager.OpenWrite(outputPath);

TraceLogger.WriteActionEnd();

DecryptStream(inFile, outFile, progressCallback);
}

catch(Exception error)
{
TraceLogger.WriteError(error, "Failed to Decrypt file");
}

TraceLogger.WriteLine("Cdat Decryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

}

}