using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;

namespace UdsLogParser
{
    class Program
    {
        // Dictionary mapping UDS SIDs to service names (request and response)
        private static readonly Dictionary<byte, string> UdsServices = new Dictionary<byte, string>
        {
            { 0x10, "Diagnostic Session Control (Request)" },
            { 0x50, "Diagnostic Session Control (Response)" },
            { 0x11, "ECU Reset (Request)" },
            { 0x51, "ECU Reset (Response)" },
            { 0x22, "Read Data By Identifier (Request)" },
            { 0x62, "Read Data By Identifier (Response)" },
            { 0x27, "Security Access (Request)" },
            { 0x67, "Security Access (Response)" },
            { 0x2E, "Write Data By Identifier (Request)" },
            { 0x6E, "Write Data By Identifier (Response)" },
            { 0x31, "Routine Control (Request)" },
            { 0x71, "Routine Control (Response)" },
            { 0x34, "Request Download (Request)" },
            { 0x74, "Request Download (Response)" },
            { 0x36, "Transfer Data (Request)" },
            { 0x76, "Transfer Data (Response)" },
            { 0x7F, "Negative Response" }
        };

        static void Main(string[] args)
        {
            // Check if a file path was provided
            if (args == null || args.Length == 0)
            {
            args = [@"d:\OneDrive\Documents\Integrated Engineering\mg1cs002-stockmapsflash.candata"];
            }

            string filePath = args[0];

            try
            {
                // Check if the file exists
                if (!File.Exists(filePath))
                {
                    Console.WriteLine($"Error: File '{filePath}' does not exist.");
                    return;
                }

                // Read the file as raw bytes
                byte[] fileBytes = File.ReadAllBytes(filePath);

                // Validate file size (must be multiple of 17 bytes)
                if (fileBytes.Length % 17 != 0)
                {
                    Console.WriteLine($"Warning: File size ({fileBytes.Length} bytes) is not a multiple of 17. Last incomplete line will be ignored.");
                }

                // List to store selected lines (17-byte arrays)
                List<byte[]> selectedLines = [];

                // Process the file in 17-byte chunks
                Console.WriteLine("Parsing UDS Log (only lines with payload byte 3 = 0x36)...");
                Console.WriteLine("Line Number | Timestamp | CAN ID | Payload | Service | Details");

                for (int i = 0; i < fileBytes.Length - 16; i += 17)
                {
                    byte[] lineBytes = [.. fileBytes.Skip(i).Take(17)];
                    if (ParseLine(lineBytes, i / 17 + 1))
                    {
                        selectedLines.Add(lineBytes);
                    }
                }

                // Save selected lines to result.bin
                try
                {
                    File.WriteAllBytes("result.bin", [.. selectedLines.SelectMany(line => line)]);
                    Console.WriteLine($"\nSaved {selectedLines.Count} selected lines to result.bin");
                }
                catch (IOException ex)
                {
                    Console.WriteLine($"Error writing to result.bin: {ex.Message}");
                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine($"Error: Access denied when writing to result.bin: {ex.Message}");
                }
            }
            catch (IOException ex)
            {
                Console.WriteLine($"Error reading file: {ex.Message}");
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine($"Error: Access denied to file '{filePath}': {ex.Message}");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Unexpected error: {ex.Message}");
            }
        }

        static bool ParseLine(byte[] lineBytes, int lineNumber)
        {
            // Validate line length (expecting 17 bytes)
            if (lineBytes.Length != 17)
            {
                Console.WriteLine($"Line {lineNumber}: Invalid format (expected 17 bytes, got {lineBytes.Length})");
                return false;
            }

            try
            {
                // Extract payload (bytes 8-16, index 8-16)
                byte[] payload = [.. lineBytes.Skip(8).Take(9)];

                // Check byte 3 of payload (index 2 in payload, byte 10 in line)
                if (payload[2] != 0x36)
                {
                    return false; // Skip lines where payload byte 3 is not 0x36
                }

                // Extract Timestamp (bytes 0-3, index 0-3)
                uint timestamp = BitConverter.ToUInt32([.. lineBytes.Take(4).Reverse()], 0); // Reverse for big-endian
                string timestampHex = string.Join(" ", lineBytes.Take(4).Select(b => b.ToString("X2")));

                // Extract CAN ID (bytes 4-7, index 4-7)
                string canId = string.Join(" ", lineBytes.Skip(4).Take(4).Select(b => b.ToString("X2")));

                // Payload hex for display
                string payloadHex = string.Join(" ", payload.Select(b => b.ToString("X2")));

                // Parse the payload for UDS service
                string service = "Unknown";
                string details = "";

                // Check byte 8 (index 0 in payload) for PCI
                byte pciByte = payload[0];

                if (pciByte == 0x30 && payload[1] == 0x00)
                {
                    // Flow Control frame (should not occur with SID 0x36)
                    service = "Flow Control";
                    details = "ISO-TP Flow Control frame (unexpected with SID 0x36)";
                }
                else if ((pciByte & 0xF0) == 0x00) // Single Frame (0x0N)
                {
                    // SID is in byte 10 (index 2 in payload), already verified as 0x36
                    byte sid = payload[2];
                    if (UdsServices.ContainsKey(sid))
                    {
                        service = UdsServices[sid];
                        // Include subfunction or data
                        details = GetServiceDetails(sid, [.. payload.Skip(3)]);
                    }
                    else
                    {
                        service = "Proprietary/Unknown";
                        details = $"SID: 0x{sid:X2} (unexpected)";
                    }
                }
                else if ((pciByte & 0xF0) == 0x10) // First Frame (0x1N)
                {
                    // SID is in byte 10 (index 2 in payload), already verified as 0x36
                    byte sid = payload[2];
                    if (UdsServices.ContainsKey(sid))
                    {
                        service = UdsServices[sid];
                        // Extract length (bytes 8-9, index 0-1 in payload)
                        int length = ((pciByte & 0x0F) << 8) | payload[1];
                        details = $"First Frame, Length: {length} bytes, {GetServiceDetails(sid, [.. payload.Skip(3)])}";
                    }
                    else
                    {
                        service = "Proprietary/Unknown";
                        details = $"SID: 0x{sid:X2} (unexpected)";
                    }
                }
                else if ((pciByte & 0xF0) == 0x20) // Consecutive Frame (0x2N)
                {
                    service = "Consecutive Frame";
                    details = $"Sequence Number: {(pciByte & 0x0F)}, Part of multi-frame Transfer Data (0x36) message";
                }
                else
                {
                    // Non-standard or proprietary
                    service = "Proprietary/Unknown";
                    details = $"Possible proprietary frame, Byte 8: 0x{pciByte:X2}, SID: 0x36";
                }

                // Output the parsed information
                Console.WriteLine($"Line {lineNumber,-10} | {timestampHex,-14} | {canId,-14} | {payloadHex,-26} | {service,-30} | {details}");

                return true; // Line was selected (payload[2] == 0x36)
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Line {lineNumber}: Error parsing line - {ex.Message}");
                return false;
            }
        }

        static string GetServiceDetails(byte sid, byte[] data)
        {
            if (data.Length == 0)
                return "";

            switch (sid)
            {
                case 0x36: // Transfer Data
                    return $"Block Sequence Counter: 0x{data[0]:X2}, Data: {string.Join(" ", data.Skip(1).Select(b => b.ToString("X2")))}";
                case 0x76:
                    return $"Block Sequence Counter: 0x{data[0]:X2}, Data: {string.Join(" ", data.Skip(1).Select(b => b.ToString("X2")))}";
                default:
                    return $"Data: {string.Join(" ", data.Select(b => b.ToString("X2")))}";
            }
        }

        static string GetSessionType(byte subfunction)
        {
            return subfunction switch
            {
                0x01 => "Default Session",
                0x02 => "Programming Session",
                0x03 => "Extended Diagnostic Session",
                _ => "Unknown Session"
            };
        }

        static string GetErrorCodeDescription(byte errorCode)
        {
            return errorCode switch
            {
                0x10 => "General Reject",
                0x11 => "Service Not Supported",
                0x12 => "Subfunction Not Supported",
                0x13 => "Incorrect Message Length or Invalid Format",
                0x22 => "Conditions Not Correct",
                0x31 => "Request Out of Range",
                0x33 => "Security Access Denied",
                0x78 => "Request Correctly Received, Response Pending",
                _ => "Unknown Error"
            };
        }
    }
}

// namespace UdsLogParser
// {
//     class Program
//     {
//         // Dictionary mapping UDS SIDs to service names (request and response)
//         private static readonly Dictionary<byte, string> UdsServices = new Dictionary<byte, string>
//         {
//             { 0x10, "Diagnostic Session Control (Request)" },
//             { 0x50, "Diagnostic Session Control (Response)" },
//             { 0x11, "ECU Reset (Request)" },
//             { 0x51, "ECU Reset (Response)" },
//             { 0x22, "Read Data By Identifier (Request)" },
//             { 0x62, "Read Data By Identifier (Response)" },
//             { 0x27, "Security Access (Request)" },
//             { 0x67, "Security Access (Response)" },
//             { 0x2E, "Write Data By Identifier (Request)" },
//             { 0x6E, "Write Data By Identifier (Response)" },
//             { 0x31, "Routine Control (Request)" },
//             { 0x71, "Routine Control (Response)" },
//             { 0x34, "Request Download (Request)" },
//             { 0x74, "Request Download (Response)" },
//             { 0x36, "Transfer Data (Request)" },
//             { 0x76, "Transfer Data (Response)" },
//             { 0x7F, "Negative Response" }
//         };

//         static void Main(string[] args)
//         {
//             // Check if a file path was provided
//             if (args == null || args.Length == 0)
//             {
//             args = [@"d:\OneDrive\Documents\Integrated Engineering\mg1cs002-stockmapsflash.candata"];
//             }

//             string filePath = args[0];

//             try
//             {
//                 // Check if the file exists
//                 if (!File.Exists(filePath))
//                 {
//                     Console.WriteLine($"Error: File '{filePath}' does not exist.");
//                     return;
//                 }

//                 // Read the file as raw bytes
//                 byte[] fileBytes = File.ReadAllBytes(filePath);

//                 // Validate file size (must be multiple of 17 bytes)
//                 if (fileBytes.Length % 17 != 0)
//                 {
//                     Console.WriteLine($"Warning: File size ({fileBytes.Length} bytes) is not a multiple of 17. Last incomplete line will be ignored.");
//                 }

//                 // Process the file in 17-byte chunks
//                 Console.WriteLine("Parsing UDS Log (only lines with payload byte 3 = 0x36)...");
//                 Console.WriteLine("Line Number | Timestamp | CAN ID | Payload | Service | Details");

//                 for (int i = 0; i < fileBytes.Length - 16; i += 17)
//                 {
//                     byte[] lineBytes = fileBytes.Skip(i).Take(17).ToArray();
//                     ParseLine(lineBytes, i / 17 + 1);
//                 }
//             }
//             catch (IOException ex)
//             {
//                 Console.WriteLine($"Error reading file: {ex.Message}");
//             }
//             catch (UnauthorizedAccessException ex)
//             {
//                 Console.WriteLine($"Error: Access denied to file '{filePath}'. {ex.Message}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Unexpected error: {ex.Message}");
//             }
//         }

//         static void ParseLine(byte[] lineBytes, int lineNumber)
//         {
//             // Validate line length (expecting 17 bytes)
//             if (lineBytes.Length != 17)
//             {
//                 Console.WriteLine($"Line {lineNumber}: Invalid format (expected 17 bytes, got {lineBytes.Length})");
//                 return;
//             }

//             try
//             {
//                 // Extract payload (bytes 8-16, index 8-16)
//                 byte[] payload = lineBytes.Skip(8).Take(9).ToArray();

//                 // Check byte 3 of payload (index 2 in payload, byte 10 in line)
//                 if (payload[2] != 0x36)
//                 {
//                     return; // Skip lines where payload byte 3 is not 0x36
//                 }

//                 // Extract Timestamp (bytes 0-3, index 0-3)
//                 uint timestamp = BitConverter.ToUInt32(lineBytes.Take(4).Reverse().ToArray(), 0); // Reverse for big-endian
//                 string timestampHex = string.Join(" ", lineBytes.Take(4).Select(b => b.ToString("X2")));

//                 // Extract CAN ID (bytes 4-7, index 4-7)
//                 string canId = string.Join(" ", lineBytes.Skip(4).Take(4).Select(b => b.ToString("X2")));

//                 // Payload hex for display
//                 string payloadHex = string.Join(" ", payload.Select(b => b.ToString("X2")));

//                 // Parse the payload for UDS service
//                 string service = "Unknown";
//                 string details = "";

//                 // Check byte 8 (index 0 in payload) for PCI
//                 byte pciByte = payload[0];

//                 if (pciByte == 0x30 && payload[1] == 0x00)
//                 {
//                     // Flow Control frame (should not occur with SID 0x36)
//                     service = "Flow Control";
//                     details = "ISO-TP Flow Control frame (unexpected with SID 0x36)";
//                 }
//                 else if ((pciByte & 0xF0) == 0x00) // Single Frame (0x0N)
//                 {
//                     // SID is in byte 10 (index 2 in payload), already verified as 0x36
//                     byte sid = payload[2];
//                     if (UdsServices.ContainsKey(sid))
//                     {
//                         service = UdsServices[sid];
//                         // Include subfunction or data
//                         details = GetServiceDetails(sid, payload.Skip(3).ToArray());
//                     }
//                     else
//                     {
//                         service = "Proprietary/Unknown";
//                         details = $"SID: 0x{sid:X2} (unexpected)";
//                     }
//                 }
//                 else if ((pciByte & 0xF0) == 0x10) // First Frame (0x1N)
//                 {
//                     // SID is in byte 10 (index 2 in payload), already verified as 0x36
//                     byte sid = payload[2];
//                     if (UdsServices.ContainsKey(sid))
//                     {
//                         service = UdsServices[sid];
//                         // Extract length (bytes 8-9, index 0-1 in payload)
//                         int length = ((pciByte & 0x0F) << 8) | payload[1];
//                         details = $"First Frame, Length: {length} bytes, {GetServiceDetails(sid, payload.Skip(3).ToArray())}";
//                     }
//                     else
//                     {
//                         service = "Proprietary/Unknown";
//                         details = $"SID: 0x{sid:X2} (unexpected)";
//                     }
//                 }
//                 else if ((pciByte & 0xF0) == 0x20) // Consecutive Frame (0x2N)
//                 {
//                     service = "Consecutive Frame";
//                     details = $"Sequence Number: {(pciByte & 0x0F)}, Part of multi-frame Transfer Data (0x36) message";
//                 }
//                 else
//                 {
//                     // Non-standard or proprietary
//                     service = "Proprietary/Unknown";
//                     details = $"Possible proprietary frame, Byte 8: 0x{pciByte:X2}, SID: 0x36";
//                 }

//                 // Output the parsed information
//                 Console.WriteLine($"Line {lineNumber,-10} | {timestampHex,-14} | {canId,-14} | {payloadHex,-26} | {service,-30} | {details}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Line {lineNumber}: Error parsing line - {ex.Message}");
//             }
//         }

//         static string GetServiceDetails(byte sid, byte[] data)
//         {
//             if (data.Length == 0)
//                 return "";

//             switch (sid)
//             {
//                 case 0x36: // Transfer Data
//                     return $"Block Sequence Counter: 0x{data[0]:X2}, Data: {string.Join(" ", data.Skip(1).Select(b => b.ToString("X2")))}";
//                 case 0x76:
//                     return $"Block Sequence Counter: 0x{data[0]:X2}, Data: {string.Join(" ", data.Skip(1).Select(b => b.ToString("X2")))}";
//                 default:
//                     return $"Data: {string.Join(" ", data.Select(b => b.ToString("X2")))}";
//             }
//         }

//         static string GetSessionType(byte subfunction)
//         {
//             return subfunction switch
//             {
//                 0x01 => "Default Session",
//                 0x02 => "Programming Session",
//                 0x03 => "Extended Diagnostic Session",
//                 _ => "Unknown Session"
//             };
//         }

//         static string GetErrorCodeDescription(byte errorCode)
//         {
//             return errorCode switch
//             {
//                 0x10 => "General Reject",
//                 0x11 => "Service Not Supported",
//                 0x12 => "Subfunction Not Supported",
//                 0x13 => "Incorrect Message Length or Invalid Format",
//                 0x22 => "Conditions Not Correct",
//                 0x31 => "Request Out of Range",
//                 0x33 => "Security Access Denied",
//                 0x78 => "Request Correctly Received, Response Pending",
//                 _ => "Unknown Error"
//             };
//         }
//     }
// }

// using System;
// using System.Collections.Generic;
// using System.IO;
// using System.Linq;

// namespace UdsLogParser
// {
//     class Program
//     {
//         // Dictionary mapping UDS SIDs to service names (request and response)
//         private static readonly Dictionary<byte, string> UdsServices = new Dictionary<byte, string>
//         {
//             { 0x10, "Diagnostic Session Control (Request)" },
//             { 0x50, "Diagnostic Session Control (Response)" },
//             { 0x11, "ECU Reset (Request)" },
//             { 0x51, "ECU Reset (Response)" },
//             { 0x22, "Read Data By Identifier (Request)" },
//             { 0x62, "Read Data By Identifier (Response)" },
//             { 0x27, "Security Access (Request)" },
//             { 0x67, "Security Access (Response)" },
//             { 0x2E, "Write Data By Identifier (Request)" },
//             { 0x6E, "Write Data By Identifier (Response)" },
//             { 0x31, "Routine Control (Request)" },
//             { 0x71, "Routine Control (Response)" },
//             { 0x34, "Request Download (Request)" },
//             { 0x74, "Request Download (Response)" },
//             { 0x36, "Transfer Data (Request)" },
//             { 0x76, "Transfer Data (Response)" },
//             { 0x7F, "Negative Response" }
//         };

//         static void Main(string[] args)
//         {
//             // Check if a file path was provided
//             if (args == null || args.Length == 0)
//             {
//             args = [@"d:\OneDrive\Documents\Integrated Engineering\mg1cs002-stockmapsflash.candata"];
//             }

//             string filePath = args[0];

//             try
//             {
//                 // Check if the file exists
//                 if (!File.Exists(filePath))
//                 {
//                     Console.WriteLine($"Error: File '{filePath}' does not exist.");
//                     return;
//                 }

//                 // Read the file as raw bytes
//                 byte[] fileBytes = File.ReadAllBytes(filePath);

//                 // Validate file size (must be multiple of 17 bytes)
//                 if (fileBytes.Length % 17 != 0)
//                 {
//                     Console.WriteLine($"Warning: File size ({fileBytes.Length} bytes) is not a multiple of 17. Last incomplete line will be ignored.");
//                 }

//                 // Process the file in 17-byte chunks
//                 Console.WriteLine("Parsing UDS Log...");
//                 Console.WriteLine("Line Number | Timestamp | CAN ID | Payload | Service | Details");

//                 for (int i = 0; i < fileBytes.Length - 16; i += 17)
//                 {
//                     byte[] lineBytes = fileBytes.Skip(i).Take(17).ToArray();
//                     ParseLine(lineBytes, i / 17 + 1);
//                 }
//             }
//             catch (IOException ex)
//             {
//                 Console.WriteLine($"Error reading file: {ex.Message}");
//             }
//             catch (UnauthorizedAccessException ex)
//             {
//                 Console.WriteLine($"Error: Access denied to file '{filePath}'. {ex.Message}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Unexpected error: {ex.Message}");
//             }
//         }

//         static void ParseLine(byte[] lineBytes, int lineNumber)
//         {
//             // Validate line length (expecting 17 bytes)
//             if (lineBytes.Length != 17)
//             {
//                 Console.WriteLine($"Line {lineNumber}: Invalid format (expected 17 bytes, got {lineBytes.Length})");
//                 return;
//             }

//             try
//             {
//                 // Extract Timestamp (bytes 0-3, index 0-3)
//                 uint timestamp = BitConverter.ToUInt32(lineBytes.Take(4).Reverse().ToArray(), 0); // Reverse for big-endian
//                 string timestampHex = string.Join(" ", lineBytes.Take(4).Select(b => b.ToString("X2")));

//                 // Extract CAN ID (bytes 4-7, index 4-7)
//                 string canId = string.Join(" ", lineBytes.Skip(4).Take(4).Select(b => b.ToString("X2")));

//                 // Extract payload (bytes 8-16, index 8-16)
//                 byte[] payload = lineBytes.Skip(8).Take(9).ToArray();
//                 string payloadHex = string.Join(" ", payload.Select(b => b.ToString("X2")));

//                 // Parse the payload for UDS service
//                 string service = "Unknown";
//                 string details = "";

//                 // Check byte 8 (index 0 in payload) for PCI
//                 byte pciByte = payload[0];

//                 if (pciByte == 0x30 && payload[1] == 0x00)
//                 {
//                     // Flow Control frame
//                     service = "Flow Control";
//                     details = "ISO-TP Flow Control frame";
//                 }
//                 else if ((pciByte & 0xF0) == 0x00) // Single Frame (0x0N)
//                 {
//                     // SID is in byte 9 (index 1 in payload)
//                     byte sid = payload[1];
//                     if (UdsServices.ContainsKey(sid))
//                     {
//                         service = UdsServices[sid];
//                         if (sid == 0x7F)
//                         {
//                             // Negative Response: include original SID and error code
//                             byte originalSid = payload[2];
//                             byte errorCode = payload[3];
//                             details = $"Original SID: 0x{originalSid:X2} ({UdsServices.GetValueOrDefault(originalSid, "Unknown")}), " +
//                                       $"Error Code: 0x{errorCode:X2} ({GetErrorCodeDescription(errorCode)})";
//                         }
//                         else
//                         {
//                             // Include subfunction or DID if applicable
//                             details = GetServiceDetails(sid, payload.Skip(2).ToArray());
//                         }
//                     }
//                     else
//                     {
//                         service = "Proprietary/Unknown";
//                         details = $"SID: 0x{sid:X2}";
//                     }
//                 }
//                 else if ((pciByte & 0xF0) == 0x10) // First Frame (0x1N)
//                 {
//                     // SID is in byte 10 (index 2 in payload)
//                     byte sid = payload[2];
//                     if (UdsServices.ContainsKey(sid))
//                     {
//                         service = UdsServices[sid];
//                         // Extract length (bytes 8-9, index 0-1 in payload)
//                         int length = ((pciByte & 0x0F) << 8) | payload[1];
//                         details = $"First Frame, Length: {length} bytes, {GetServiceDetails(sid, payload.Skip(3).ToArray())}";
//                     }
//                     else
//                     {
//                         service = "Proprietary/Unknown";
//                         details = $"SID: 0x{sid:X2}";
//                     }
//                 }
//                 else if ((pciByte & 0xF0) == 0x20) // Consecutive Frame (0x2N)
//                 {
//                     service = "Consecutive Frame";
//                     details = $"Sequence Number: {(pciByte & 0x0F)}, Part of multi-frame message";
//                 }
//                 else
//                 {
//                     // Non-standard or proprietary
//                     service = "Proprietary/Unknown";
//                     details = $"Possible proprietary frame, Byte 8: 0x{pciByte:X2}";
//                 }

//                 // Output the parsed information
//                 Console.WriteLine($"Line {lineNumber,-10} | {timestampHex,-14} | {canId,-14} | {payloadHex,-26} | {service,-30} | {details}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Line {lineNumber}: Error parsing line - {ex.Message}");
//             }
//         }

//         static string GetServiceDetails(byte sid, byte[] data)
//         {
//             if (data.Length == 0)
//                 return "";

//             switch (sid)
//             {
//                 case 0x10: // Diagnostic Session Control
//                     return $"Subfunction: 0x{data[0]:X2} ({GetSessionType(data[0])})";
//                 case 0x50:
//                     return $"Subfunction: 0x{data[0]:X2} ({GetSessionType(data[0])})";
//                 case 0x22: // Read Data By Identifier
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}";
//                     return "";
//                 case 0x62:
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}, Data: {string.Join(" ", data.Skip(2).Select(b => b.ToString("X2")))}";
//                     return "";
//                 case 0x2E: // Write Data By Identifier
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}, Data: {string.Join(" ", data.Skip(2).Select(b => b.ToString("X2")))}";
//                     break;
//                 case 0x6E:
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}";
//                     break;
//                 case 0x27: // Security Access
//                     return $"Subfunction: 0x{data[0]:X2} ({(data[0] % 2 == 1 ? "Request Seed" : "Send Key")})";
//                 case 0x67:
//                     return $"Subfunction: 0x{data[0]:X2}, Data: {string.Join(" ", data.Skip(1).Select(b => b.ToString("X2")))}";
//                 default:
//                     return $"Data: {string.Join(" ", data.Select(b => b.ToString("X2")))}";
//             }

//             return "Unknown Service Details";
//         }

//         static string GetSessionType(byte subfunction)
//         {
//             return subfunction switch
//             {
//                 0x01 => "Default Session",
//                 0x02 => "Programming Session",
//                 0x03 => "Extended Diagnostic Session",
//                 _ => "Unknown Session"
//             };
//         }

//         static string GetErrorCodeDescription(byte errorCode)
//         {
//             return errorCode switch
//             {
//                 0x10 => "General Reject",
//                 0x11 => "Service Not Supported",
//                 0x12 => "Subfunction Not Supported",
//                 0x13 => "Incorrect Message Length or Invalid Format",
//                 0x22 => "Conditions Not Correct",
//                 0x31 => "Request Out of Range",
//                 0x33 => "Security Access Denied",
//                 0x78 => "Request Correctly Received, Response Pending",
//                 _ => "Unknown Error"
//             };
//         }
//     }
// }

// namespace UdsLogParser
// {
//     class Program
//     {
//         // Dictionary mapping UDS SIDs to service names (request and response)
//         private static readonly Dictionary<byte, string> UdsServices = new Dictionary<byte, string>
//         {
//             { 0x10, "Diagnostic Session Control (Request)" },
//             { 0x50, "Diagnostic Session Control (Response)" },
//             { 0x11, "ECU Reset (Request)" },
//             { 0x51, "ECU Reset (Response)" },
//             { 0x22, "Read Data By Identifier (Request)" },
//             { 0x62, "Read Data By Identifier (Response)" },
//             { 0x27, "Security Access (Request)" },
//             { 0x67, "Security Access (Response)" },
//             { 0x2E, "Write Data By Identifier (Request)" },
//             { 0x6E, "Write Data By Identifier (Response)" },
//             { 0x31, "Routine Control (Request)" },
//             { 0x71, "Routine Control (Response)" },
//             { 0x34, "Request Download (Request)" },
//             { 0x74, "Request Download (Response)" },
//             { 0x36, "Transfer Data (Request)" },
//             { 0x76, "Transfer Data (Response)" },
//             { 0x7F, "Negative Response" }
//         };

//         static void Main(string[] args)
//         {
//             // Check if a file path was provided
//             if (args == null || args.Length == 0)
//             {
//             args = [@"d:\OneDrive\Documents\Integrated Engineering\mg1cs002-stockmapsflash.candata"];
//             }

//             string filePath = args[0];

//             try
//             {
//                 // Check if the file exists
//                 if (!File.Exists(filePath))
//                 {
//                     Console.WriteLine($"Error: File '{filePath}' does not exist.");
//                     return;
//                 }

//                 // Read the file as raw bytes
//                 byte[] fileBytes = File.ReadAllBytes(filePath);

//                 // Validate file size (must be multiple of 17 bytes)
//                 if (fileBytes.Length % 17 != 0)
//                 {
//                     Console.WriteLine($"Warning: File size ({fileBytes.Length} bytes) is not a multiple of 17. Last incomplete line will be ignored.");
//                 }

//                 // Process the file in 17-byte chunks
//                 Console.WriteLine("Parsing UDS Log...");
//                 Console.WriteLine("Line Number | CAN ID | Payload | Service | Details");

//                 for (int i = 0; i < fileBytes.Length - 16; i += 17)
//                 {
//                     byte[] lineBytes = fileBytes.Skip(i).Take(17).ToArray();
//                     ParseLine(lineBytes, i / 17 + 1);
//                 }
//             }
//             catch (IOException ex)
//             {
//                 Console.WriteLine($"Error reading file: {ex.Message}");
//             }
//             catch (UnauthorizedAccessException ex)
//             {
//                 Console.WriteLine($"Error: Access denied to file '{filePath}'. {ex.Message}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Unexpected error: {ex.Message}");
//             }
//         }

//         static void ParseLine(byte[] lineBytes, int lineNumber)
//         {
//             // Validate line length (expecting 17 bytes)
//             if (lineBytes.Length != 17)
//             {
//                 Console.WriteLine($"Line {lineNumber}: Invalid format (expected 17 bytes, got {lineBytes.Length})");
//                 return;
//             }

//             try
//             {
//                 // Extract CAN ID (bytes 1-4, index 0-3)
//                 string canId = string.Join(" ", lineBytes.Take(4).Select(b => b.ToString("X2")));
//                 // Extract payload (bytes 5-12, index 4-11)
//                 byte[] payload = lineBytes.Skip(4).Take(8).ToArray();
//                 string payloadHex = string.Join(" ", payload.Select(b => b.ToString("X2")));
//                 // Check padding (bytes 13-17, index 12-16, typically 0x55)
//                 bool isPadded = lineBytes.Skip(12).All(b => b == 0x55);

//                 // Parse the payload for UDS service
//                 string service = "Unknown";
//                 string details = "";

//                 // Check byte 9 (index 4 in payload, byte 5 in line) for PCI or length
//                 byte pciByte = payload[4];

//                 if (pciByte == 0x30 && payload[5] == 0x00)
//                 {
//                     // Flow Control frame
//                     service = "Flow Control";
//                     details = "ISO-TP Flow Control frame";
//                 }
//                 else if ((pciByte & 0xF0) == 0x00) // Single Frame (0x0N)
//                 {
//                     // SID is in byte 10 (index 5 in payload)
//                     byte sid = payload[5];
//                     if (UdsServices.ContainsKey(sid))
//                     {
//                         service = UdsServices[sid];
//                         if (sid == 0x7F)
//                         {
//                             // Negative Response: include original SID and error code
//                             byte originalSid = payload[6];
//                             byte errorCode = payload[7];
//                             details = $"Original SID: 0x{originalSid:X2} ({UdsServices.GetValueOrDefault(originalSid, "Unknown")}), " +
//                                       $"Error Code: 0x{errorCode:X2} ({GetErrorCodeDescription(errorCode)})";
//                         }
//                         else
//                         {
//                             // Include subfunction or DID if applicable
//                             details = GetServiceDetails(sid, payload.Skip(6).ToArray());
//                         }
//                     }
//                     else
//                     {
//                         service = "Proprietary/Unknown";
//                         details = $"SID: 0x{sid:X2}";
//                     }
//                 }
//                 else if ((pciByte & 0xF0) == 0x10) // First Frame (0x1N)
//                 {
//                     // SID is in byte 11 (index 6 in payload)
//                     byte sid = payload[6];
//                     if (UdsServices.ContainsKey(sid))
//                     {
//                         service = UdsServices[sid];
//                         // Extract length (bytes 9-10, index 4-5 in payload)
//                         int length = ((pciByte & 0x0F) << 8) | payload[5];
//                         details = $"First Frame, Length: {length} bytes, {GetServiceDetails(sid, payload.Skip(7).ToArray())}";
//                     }
//                     else
//                     {
//                         service = "Proprietary/Unknown";
//                         details = $"SID: 0x{sid:X2}";
//                     }
//                 }
//                 else if ((pciByte & 0xF0) == 0x20) // Consecutive Frame (0x2N)
//                 {
//                     service = "Consecutive Frame";
//                     details = $"Sequence Number: {(pciByte & 0x0F)}, Part of multi-frame message";
//                 }
//                 else
//                 {
//                     // Non-standard or proprietary
//                     service = "Proprietary/Unknown";
//                     details = $"Possible proprietary frame, Byte 9: 0x{pciByte:X2}";
//                 }

//                 // Output the parsed information
//                 Console.WriteLine($"Line {lineNumber,-10} | {canId,-14} | {payloadHex,-23} | {service,-30} | {details}");
//             }
//             catch (Exception ex)
//             {
//                 Console.WriteLine($"Line {lineNumber}: Error parsing line - {ex.Message}");
//             }
//         }

//         static string GetServiceDetails(byte sid, byte[] data)
//         {
//             if (data.Length == 0)
//                 return "";

//             switch (sid)
//             {
//                 case 0x10: // Diagnostic Session Control
//                     return $"Subfunction: 0x{data[0]:X2} ({GetSessionType(data[0])})";
//                 case 0x50:
//                     return $"Subfunction: 0x{data[0]:X2} ({GetSessionType(data[0])})";
//                 case 0x22: // Read Data By Identifier
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}";
//                     return "";
//                 case 0x62:
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}, Data: {string.Join(" ", data.Skip(2).Select(b => b.ToString("X2")))}";
//                     return "";
//                 case 0x2E: // Write Data By Identifier
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}, Data: {string.Join(" ", data.Skip(2).Select(b => b.ToString("X2")))}";
//                     break;
//                 case 0x6E:
//                     if (data.Length >= 2)
//                         return $"DID: 0x{data[0]:X2}{data[1]:X2}";
//                     break;
//                 case 0x27: // Security Access
//                     return $"Subfunction: 0x{data[0]:X2} ({(data[0] % 2 == 1 ? "Request Seed" : "Send Key")})";
//                 case 0x67:
//                     return $"Subfunction: 0x{data[0]:X2}, Data: {string.Join(" ", data.Skip(1).Select(b => b.ToString("X2")))}";
//                 default:
//                     return $"Data: {string.Join(" ", data.Select(b => b.ToString("X2")))}";
//             }

//             return "Unknown Service Details";
//         }

//         static string GetSessionType(byte subfunction)
//         {
//             return subfunction switch
//             {
//                 0x01 => "Default Session",
//                 0x02 => "Programming Session",
//                 0x03 => "Extended Diagnostic Session",
//                 _ => "Unknown Session"
//             };
//         }

//         static string GetErrorCodeDescription(byte errorCode)
//         {
//             return errorCode switch
//             {
//                 0x10 => "General Reject",
//                 0x11 => "Service Not Supported",
//                 0x12 => "Subfunction Not Supported",
//                 0x13 => "Incorrect Message Length or Invalid Format",
//                 0x22 => "Conditions Not Correct",
//                 0x31 => "Request Out of Range",
//                 0x33 => "Security Access Denied",
//                 0x78 => "Request Correctly Received, Response Pending",
//                 _ => "Unknown Error"
//             };
//         }
//     }
// }

// namespace FileReaderConsole
// {
//     class Program
//     {
//         static void Main(string[] args)
//         {
//             // Set a default file path if args is null or empty
//             if (args == null || args.Length == 0)
//             {
//             args = [@"d:\OneDrive\Documents\Integrated Engineering\mg1cs002-stockmapsflash.candata"];
//             }

//             string filePath = args[0];

//             try
//             {
//             // Check if the file exists
//             if (!File.Exists(filePath))
//             {
//                 Console.WriteLine($"Error: File '{filePath}' does not exist.");
//                 return;
//             }

//             // Read the entire file into a string
//             string fileContent = File.ReadAllText(filePath);

//             // Output the file content
//             Console.WriteLine("File Contents:");
//             Console.WriteLine(fileContent);
//             }
//             catch (IOException ex)
//             {
//             Console.WriteLine($"Error reading file: {ex.Message}");
//             }
//             catch (UnauthorizedAccessException ex)
//             {
//             Console.WriteLine($"Error: Access denied to file '{filePath}'. {ex.Message}");
//             }
//             catch (Exception ex)
//             {
//             Console.WriteLine($"Unexpected error: {ex.Message}");
//             }
//         }
//     }
// }