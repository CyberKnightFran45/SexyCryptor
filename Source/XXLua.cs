using BlossomLib.Modules.Security;
using System;
using System.IO;

namespace SexyCryptor
{
/// <summary> Ciphers Lua Files from PvZ All Stars by using the XXTea Algorithm. </summary>

public static class XXLua
{
/// <summary> The Header of an Encrypted Lua Script. </summary>

private const string HEADER = "XXTEA";

/// <summary> The Key used. </summary>

private static readonly byte[] KEY = "7ec34b808tk94hf1"u8.ToArray();

// Get XXTea Stream

public static void EncryptStream(Stream input, Stream output)
{
long inputLen = input.Length;

string fileSize = SizeT.FormatSize(inputLen);
TraceLogger.WriteActionStart($"Reading input data... ({fileSize})");

using NativeMemoryOwner<byte> bOwner = new(inputLen);
var inputBytes = bOwner.AsSpan();

input.ReadExactly(inputBytes);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Encrypting data...");
using var encOwner = XXTeaCryptor.EncryptData(inputBytes, KEY);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting header...");
output.WriteString(HEADER);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting encrypted data...");
output.Write(encOwner.AsSpan() );

TraceLogger.WriteActionEnd();
}

/** <summary> Encrypts a File by using XXTea. </summary>

<param name = "inputPath"> The Path where the File to Encrypt is Located. </param>
<param name = "outputPath"> The Path where the Encrypted File will be Saved. </param> */

public static void EncryptFile(string inputPath, string outputPath)
{
TraceLogger.Init();
TraceLogger.WriteLine("XXLua Encryption Started");

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

TraceLogger.WriteLine("XXLua Encryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

// Get Plain Stream

public static void DecryptStream(Stream input, Stream output)
{
TraceLogger.WriteActionStart("Reading header...");

using var hOwner = input.ReadString(HEADER.Length);
var inputHeader = hOwner.AsSpan();

if(!inputHeader.SequenceEqual(HEADER) )
{
TraceLogger.WriteError($"Invalid header: \"{inputHeader}\", expected: \"{HEADER}\"");
return;
}

TraceLogger.WriteActionEnd();

long inputLen = input.Length - HEADER.Length;
string fileSize = SizeT.FormatSize(inputLen);

TraceLogger.WriteActionStart($"Reading encrypted data... ({fileSize})");

using NativeMemoryOwner<byte> bOwner = new(inputLen);

var inputBytes = bOwner.AsSpan();
input.ReadExactly(inputBytes);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Decrypting data...");
using var decOwner = XXTeaCryptor.DecryptData(inputBytes, KEY);

TraceLogger.WriteActionEnd();

TraceLogger.WriteActionStart("Writting output data...");
output.Write(decOwner.AsSpan() );

TraceLogger.WriteActionEnd();
}

/** <summary> Decrypts a File by using XXTea. </summary>

<param name = "inputPath"> The Path where the File Decrypt is Located. </param>
<param name = "outputPath"> The Path where the Decrypted File will be Saved. </param> */

public static void DecryptFile(string inputPath, string outputPath)
{
TraceLogger.Init();
TraceLogger.WriteLine("XXLua Decryption Started");

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

TraceLogger.WriteLine("XXLua Decryption Finished");

var outSize = FileManager.GetFileSize(outputPath);
TraceLogger.WriteInfo($"Output Size: {SizeT.FormatSize(outSize)}", false);
}

}

}