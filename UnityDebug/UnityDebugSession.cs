/*---------------------------------------------------------------------------------------------
 *  Copyright (c) Microsoft Corporation. All rights reserved.
 *  Copyright (c) Unity Technologies.
 *  Licensed under the MIT License. See License.txt in the project root for license information.
 *--------------------------------------------------------------------------------------------*/

using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.VisualStudio.Shared.VSCodeDebugProtocol;
using Microsoft.VisualStudio.Shared.VSCodeDebugProtocol.Messages;
using Mono.Debugging.Client;
using Mono.Debugging.Soft;
using MonoDevelop.Debugger.Soft.Unity;
using Newtonsoft.Json.Linq;
using Breakpoint = Mono.Debugging.Client.Breakpoint;
using StackFrame = Mono.Debugging.Client.StackFrame;
using DapThread = Microsoft.VisualStudio.Shared.VSCodeDebugProtocol.Messages.Thread;

namespace UnityDebug
{
    internal class UnityDebugSession : DebugAdapterBase
    {
        readonly string[] MONO_EXTENSIONS =
        {
            ".cs", ".csx",
            ".cake",
            ".fs", ".fsi", ".ml", ".mli", ".fsx", ".fsscript",
            ".hx"
        };
        const int MAX_CHILDREN = 100;
        const int MAX_CONNECTION_ATTEMPTS = 10;
        const int CONNECTION_ATTEMPT_INTERVAL = 500;

        AutoResetEvent m_ResumeEvent;
        bool m_DebuggeeExecuting;
        readonly object m_Lock = new object();
        SoftDebuggerSession m_Session;
        ProcessInfo m_ActiveProcess;
        Dictionary<string, Dictionary<int, Breakpoint>> m_Breakpoints;
        List<Catchpoint> m_Catchpoints;
        DebuggerSessionOptions m_DebuggerSessionOptions;

        VSCodeDebug.Handles<ObjectValue[]> m_VariableHandles;
        VSCodeDebug.Handles<StackFrame> m_FrameHandles;
        ObjectValue m_Exception;
        Dictionary<int, DapThread> m_SeenThreads;
        bool m_Terminated;
        IUnityDbgConnector unityDebugConnector;

        public UnityDebugSession(Stream stdIn, Stream stdOut)
        {
            //Log.Write("Constructing UnityDebugSession");
            m_ResumeEvent = new AutoResetEvent(false);
            m_Breakpoints = new Dictionary<string, Dictionary<int, Breakpoint>>();
            m_VariableHandles = new VSCodeDebug.Handles<ObjectValue[]>();
            m_FrameHandles = new VSCodeDebug.Handles<StackFrame>();
            m_SeenThreads = new Dictionary<int, DapThread>();

            m_DebuggerSessionOptions = new DebuggerSessionOptions
            {
                EvaluationOptions = EvaluationOptions.DefaultOptions
            };

            m_Session = new UnityDebuggerSession();
            m_Session.Breakpoints = new BreakpointStore();

            m_Catchpoints = new List<Catchpoint>();

            //DebuggerLoggingService.CustomLogger = new CustomLogger();

            m_Session.ExceptionHandler = ex =>
            {
                return true;
            };

            m_Session.LogWriter = (isStdErr, text) =>
            {
                //SendOutput(isStdErr ? "stderr" : "stdout", text);
            };

            m_Session.TargetStopped += (sender, e) =>
            {
                if (e.Backtrace != null)
                {
                    Frame = e.Backtrace.GetFrame(0);
                }
                else
                {
                    this.ConsoleLog("e.Backtrace is null");
                    //SendOutput("stdout", "e.Bracktrace is null");
                }

                Stopped();
                //SendEvent(CreateStoppedEvent("step", e.Thread));
                this.Protocol.SendEvent(new StoppedEvent(StoppedEvent.ReasonValue.Step) {
                    ThreadId = (int)e.Thread.Id,
                });
                m_ResumeEvent.Set();
            };

            m_Session.TargetHitBreakpoint += (sender, e) =>
            {
                Frame = e.Backtrace.GetFrame(0);
                Stopped();
                this.Protocol.SendEvent(new StoppedEvent(StoppedEvent.ReasonValue.Breakpoint) {
                    ThreadId = (int)e.Thread.Id,
                });
                //SendEvent(CreateStoppedEvent("breakpoint", e.Thread));
                m_ResumeEvent.Set();
            };

            m_Session.TargetExceptionThrown += (sender, e) =>
            {
                Frame = e.Backtrace.GetFrame(0);
                for (var i = 0; i < e.Backtrace.FrameCount; i++)
                {
                    if (!e.Backtrace.GetFrame(i).IsExternalCode)
                    {
                        Frame = e.Backtrace.GetFrame(i);
                        break;
                    }
                }

                Stopped();
                var ex = DebuggerActiveException();
                if (ex != null)
                {
                    m_Exception = ex.Instance;
                    this.Protocol.SendEvent(new StoppedEvent(StoppedEvent.ReasonValue.Exception) {
                        ThreadId = (int)e.Thread.Id,
                        Text = ex.Message,
                    });
                    //SendEvent(CreateStoppedEvent("exception", e.Thread, ex.Message));
                }

                m_ResumeEvent.Set();
            };

            m_Session.TargetUnhandledException += (sender, e) =>
            {
                Stopped();
                var ex = DebuggerActiveException();
                if (ex != null)
                {
                    m_Exception = ex.Instance;
                    this.Protocol.SendEvent(new StoppedEvent(StoppedEvent.ReasonValue.Exception) {
                        ThreadId = (int)e.Thread.Id,
                        Text = ex.Message,
                    });
                    //SendEvent(CreateStoppedEvent("exception", e.Thread, ex.Message));
                }

                m_ResumeEvent.Set();
            };

            m_Session.TargetStarted += (sender, e) =>
            {
            };

            m_Session.TargetReady += (sender, e) =>
            {
                m_ActiveProcess = m_Session.GetProcesses().SingleOrDefault();
            };

            m_Session.TargetExited += (sender, e) =>
            {
                DebuggerKill();

                //Terminate("target exited");

                m_ResumeEvent.Set();
            };

            m_Session.TargetInterrupted += (sender, e) =>
            {
                m_ResumeEvent.Set();
            };

            m_Session.TargetEvent += (sender, e) => { };

            m_Session.TargetThreadStarted += (sender, e) =>
            {
                var tid = (int)e.Thread.Id;
                lock (m_SeenThreads)
                {
                    m_SeenThreads[tid] = new DapThread(tid, e.Thread.Name);
                }

                //SendEvent(new ThreadEvent("started", tid));
                this.Protocol.SendEvent(new ThreadEvent(ThreadEvent.ReasonValue.Started, (int)tid));
            };

            m_Session.TargetThreadStopped += (sender, e) =>
            {
                var tid = (int)e.Thread.Id;
                lock (m_SeenThreads)
                {
                    m_SeenThreads.Remove(tid);
                }

                //SendEvent(new ThreadEvent("exited", tid));
                this.Protocol.SendEvent(new ThreadEvent(ThreadEvent.ReasonValue.Exited, (int)tid));
            };

            m_Session.OutputWriter = (isStdErr, text) =>
            {
                //SendOutput(isStdErr ? "stderr" : "stdout", text);
                this.Protocol.SendEvent(new OutputEvent(text) {
                    Category = isStdErr ? OutputEvent.CategoryValue.Stderr : OutputEvent.CategoryValue.Stdout,
                });
            };

            //Log.Write("Done constructing UnityDebugSession");
            //this.ConsoleLog("Done constructing UnityDebugSession");

            this.InitializeProtocolClient(stdIn, stdOut);
        }

        public void Run()
        {
            this.Protocol.Run();
        }

        public StackFrame Frame { get; set; }

        protected override InitializeResponse HandleInitializeRequest(InitializeArguments arguments)
        {
            var os = Environment.OSVersion;
            if (os.Platform != PlatformID.MacOSX && os.Platform != PlatformID.Unix && os.Platform != PlatformID.Win32NT)
            {
                throw new ProtocolException(
                    "notsupported",
                    3000,
                    "Mono Debug is not supported on this platform ({platform}).",
                    new Dictionary<string, object>() { { "platform", os.Platform.ToString() } },
                    showUser: true
                );
            }

            this.ConsoleLog("Initializing");

            this.Protocol.SendEvent(new InitializedEvent());

            Log.Write("???");

            return new InitializeResponse() {
                // This debug adapter does not need the configurationDoneRequest.
                //supportsConfigurationDoneRequest: null,

                // This debug adapter does not support function breakpoints.
                //supportsFunctionBreakpoints: false,

                // This debug adapter support conditional breakpoints.
                SupportsConditionalBreakpoints = true,

                // This debug adapter does support a side effect free evaluate request for data hovers.
                SupportsEvaluateForHovers = true,

                SupportsExceptionOptions = true,

                SupportsHitConditionalBreakpoints = true,

                SupportsSetVariable = true

                // This debug adapter does not support exception breakpoint filters
                //exceptionBreakpointFilters: null,
            };
        }

        protected override AttachResponse HandleAttachRequest(AttachArguments arguments)
        {
            var config = arguments.ConfigurationProperties;

            //SetExceptionBreakpoints(config.__exceptionOptions);

            var projectRoot = config["projectRoot"]?.Value<string>();
            var platform = config["platform"]?.Value<string>();
            var address = config["address"]?.Value<string>() ?? "127.0.0.1";
            int port = config["port"]?.Value<int>() ?? 0;

            switch (platform) {
                case null:
                case "editor":
                    if (!this.TryGetEditorDebugPort(projectRoot, out port)) {
                        throw new ProtocolException("Could not find editor process");
                    }
                    break;
                case "android":
                    if (port == 0) {
                        var targetType = AndroidConnectionTarget.Any;
                        switch ((string)config["android"]?.Value<string>("connection")) {
                            case "usb":
                                targetType = AndroidConnectionTarget.Usb;
                                break;
                            case "ip":
                                targetType = AndroidConnectionTarget.Ip;
                                break;
                        }

                        var env = ((JObject)config["env"])?.ToObject<Dictionary<string, string>>();
                        var adb = AndroidDebugBridge.GetAndroidDebugBridge(targetType, env);

                        if (adb == null) {
                            this.ConsoleLog("Could not locate adb. Make sure adb is available via PATH or set ANDROID_SDK_ROOT environment variable.");
                            throw new ProtocolException("Could not find adb");
                        }

                        if (!adb.TryPrepareConnection(out port, out var error)) {
                            this.ConsoleLog($"Could not establish device connection using adb: {error}");
                            throw new ProtocolException($"Could not connect to unity: {error}");
                        }
                    }
                    break;
            }

            this.ConsoleLog($"Attempting SDB connection to {address}:{port}");

            IPAddress hostIp;
            try {
                // Get first valid IPv4 address
                hostIp = Dns.GetHostAddresses(address)
                    .Where(ip => ip.AddressFamily == AddressFamily.InterNetwork)
                    .FirstOrDefault();
            }
            catch (Exception e) {
                throw new ProtocolException("Could not resolve SDB host", e);
            }

            this.Connect(hostIp, port);

            return new AttachResponse();

            //throw new ProtocolException("Attaching by process discovery is no longer supported. Please specify 'projectRoot' or an platform that supports player detection.");

            /*
            var name = config["name"].ToString();

            Log.Write($"UnityDebug: Searching for Unity process '{name}'");
            SendOutput("stdout", "UnityDebug: Searching for Unity process '" + name + "'");

            var processes = UnityAttach.GetAttachableProcesses(name).ToArray();

            if (processes.Length == 0)
            {
                Log.Write($"Could not find target name '{name}'.");
                SendErrorResponse(response, 8001, "Could not find target name '{_name}'. Is it running?", new { _name = name });
                return;
            }

            UnityProcessInfo process;
            if (processes.Length == 1)
            {
                process = processes[0];
            }
            else
            {
                if (!name.Contains("Editor"))
                {
                    TooManyInstances(response, name, processes);
                    return;
                }

                string pathToEditorInstanceJson = GetString(config, "path");
                pathToEditorInstanceJson = CleanPath(pathToEditorInstanceJson);
                if (!File.Exists(pathToEditorInstanceJson))
                {
                    TooManyInstances(response, name, processes);
                    return;
                }

                var jObject = JObject.Parse(File.ReadAllText(pathToEditorInstanceJson.TrimStart('/')));
                var processId = jObject["process_id"].ToObject<int>();
                process = processes.First(p => p.Id == processId);
            }

            var attachInfo = UnityProcessDiscovery.GetUnityAttachInfo(process.Id, ref unityDebugConnector);

            Connect(attachInfo.Address, attachInfo.Port);

            Log.Write($"UnityDebug: Attached to Unity process '{process.Name}' ({process.Id})");
            SendOutput("stdout", "UnityDebug: Attached to Unity process '" + process.Name + "' (" + process.Id + ")\n");
            SendResponse(response);
            */
        }


        private bool TryGetEditorDebugPort(string projectRoot, out int port)
        {
            port = 0;

            if (projectRoot == null) {
                this.ConsoleLog("'projectRoot' configuration must be set when attaching to editor");
                return false;
            }

            this.ConsoleLog($"Checking for running editor for project at {projectRoot}");
            var pidFilePath = Path.Combine(projectRoot, "Library", "EditorInstance.json");

            if (!File.Exists(pidFilePath)) {
                return false;
            }

            var jObject = JObject.Parse(File.ReadAllText(pidFilePath));
            var pid = (jObject["process_id"].ToObject<int>() % 1000);

            this.ConsoleLog($"UnityDebug: Found editor with PID {pid}");

            port = 56000 + (pid % 1000);

            return true;
        }

        static string CleanPath(string pathToEditorInstanceJson)
        {
            var osVersion = Environment.OSVersion;
            if (osVersion.Platform == PlatformID.MacOSX || osVersion.Platform == PlatformID.Unix)
            {
                return pathToEditorInstanceJson;
            }

            return pathToEditorInstanceJson.TrimStart('/');
        }

/*
        void TooManyInstances(Response response, string name, UnityProcessInfo[] processes)
        {
            Log.Write($"Multiple targets with name '{name}' running. Unable to connect.");
            SendErrorResponse(response, 8002, "Multiple targets with name '{_name}' running. Unable to connect.\n" +
                "Use \"Unity Attach Debugger\" from the command palette (View > Command Palette...) to specify which process to attach to.", new { _name = name });

            Log.Write($"UnityDebug: Multiple targets with name '{name}' running. Unable to connect.)");
            SendOutput("stdout", "UnityDebug: Multiple targets with name '" + name + "' running. Unable to connect.\n" +
                "Use \"Unity Attach Debugger\" from the command palette (View > Command Palette...) to specify which process to attach to.");

            foreach (var p in processes)
            {
                Log.Write($"UnityDebug: Found Unity process '{p.Name}' ({p.Id})");
                SendOutput("stdout", "UnityDebug: Found Unity process '" + p.Name + "' (" + p.Id + ")\n");
            }
        }
        */

        void Connect(IPAddress address, int port)
        {
            //Log.Write($"UnityDebug: Connect to: {address}:{port}");
            this.ConsoleLog($"Connecting to: {address}:{port}...");
            lock (m_Lock)
            {
                var args0 = new SoftDebuggerConnectArgs(string.Empty, address, port)
                {
                    MaxConnectionAttempts = MAX_CONNECTION_ATTEMPTS,
                    TimeBetweenConnectionAttempts = CONNECTION_ATTEMPT_INTERVAL
                };

                m_Session.Run(new SoftDebuggerStartInfo(args0), m_DebuggerSessionOptions);

                m_DebuggeeExecuting = true;
            }
        }

        //---- private ------------------------------------------
        void SetExceptionBreakpoints(dynamic exceptionOptions)
        {
        }

        protected override DisconnectResponse HandleDisconnectRequest(DisconnectArguments arguments)
        {
            //Log.Write($"UnityDebug: Disconnect: {args}");
            //Log.Write($"UnityDebug: Disconnect: {response}");
            if (unityDebugConnector != null)
            {
                unityDebugConnector.OnDisconnect();
                unityDebugConnector = null;
            }

            lock (m_Lock)
            {
                if (m_Session != null)
                {
                    m_DebuggeeExecuting = true;
                    m_Breakpoints = null;
                    m_Session.Breakpoints.Clear();
                    m_Session.Continue();
                    m_Session.Detach();
                    m_Session.Adaptor.Dispose();
                    m_Session = null;
                }
            }

            this.ConsoleLog("Disconnected");
            //SendOutput("stdout", "UnityDebug: Disconnected");
            //SendResponse(response);
            return new DisconnectResponse();
        }

        protected override ContinueResponse HandleContinueRequest(ContinueArguments arguments)
        {
            WaitForSuspend();
            lock (m_Lock)
            {
                if ((this.m_Session?.IsRunning ?? false) && !m_Session.HasExited) {
                    m_Session.Continue();
                    m_DebuggeeExecuting = true;
                }
            }

            return new ContinueResponse();
        }

        protected override NextResponse HandleNextRequest(NextArguments arguments)
        {
            //Log.Write($"UnityDebug: Next: {response} ; {arguments}");
            WaitForSuspend();
            lock (m_Lock)
            {
                if ((this.m_Session?.IsRunning ?? false) && !this.m_Session.HasExited) {
                    m_Session.NextLine();
                    m_DebuggeeExecuting = true;
                }
            }

            return new NextResponse();
        }

        protected override StepInResponse HandleStepInRequest(StepInArguments arguments)
        {
            //Log.Write($"UnityDebug: StepIn: {response} ; {arguments}");
            WaitForSuspend();
            lock (m_Lock)
            {
                if ((this.m_Session?.IsRunning ?? false) && !this.m_Session.HasExited) {
                    m_Session.StepLine();
                    m_DebuggeeExecuting = true;
                }
            }

            return new StepInResponse();
        }

        protected override StepOutResponse HandleStepOutRequest(StepOutArguments arguments)
        {
            //Log.Write($"UnityDebug: StepIn: {response} ; {arguments}");
            WaitForSuspend();
            lock (m_Lock)
            {
                if ((this.m_Session?.IsRunning ?? false) && !this.m_Session.HasExited) {
                    m_Session.Finish();
                    m_DebuggeeExecuting = true;
                }
            }

            return new StepOutResponse();
        }

        protected override PauseResponse HandlePauseRequest(PauseArguments arguments)
        {
            //Log.Write($"UnityDebug: StepIn: {response} ; {arguments}");
            lock (m_Lock)
            {
                if (m_Session != null && m_Session.IsRunning)
                    m_Session.Stop();
            }
            return new PauseResponse();
        }

        protected override SetVariableResponse HandleSetVariableRequest(SetVariableArguments arguments)
        {
            var reference = arguments.VariablesReference;
            /*
            if (reference == -1)
            {
                throw new 
                SendErrorResponse(response, 3009, "variables: property 'variablesReference' is missing", null, false, true);
                return;
            }
            */

            var value = arguments.Value;
            if (m_VariableHandles.TryGet(reference, out var children))
            {
                if (children != null && children.Length > 0)
                {
                    if (children.Length > MAX_CHILDREN)
                    {
                        children = children.Take(MAX_CHILDREN).ToArray();
                    }

                    foreach (var v in children)
                    {
                        if (v.IsError)
                            continue;
                        v.WaitHandle.WaitOne();
                        var variable = CreateVariable(v);
                        if (variable.Name == arguments.Name)
                        {
                            v.Value = value;
                            //SendResponse(response, new SetVariablesResponseBody(value, variable.type, variable.variablesReference));
                            return new SetVariableResponse(value) {
                                Type = variable.Type,
                                VariablesReference = variable.VariablesReference,
                            };
                        }
                    }
                }
            }

            throw new ProtocolException($"Variable not found: {arguments.Name} ({arguments.VariablesReference})");
        }

        protected override SetExceptionBreakpointsResponse HandleSetExceptionBreakpointsRequest(SetExceptionBreakpointsArguments arguments)
        {
            this.ConsoleLog("setExceptionBreakpoints...");
            //Log.Write($"UnityDebug: StepIn: {response} ; {arguments}");
            var exceptionOptions = arguments.ExceptionOptions;
            if (exceptionOptions == null)
            {
                throw new ProtocolException("exceptionOptions is null");
            }

            // clear all existig catchpoints
            foreach (var cp in m_Catchpoints)
            {
                this.m_Session.Breakpoints.Remove(cp);
            }

            this.m_Catchpoints.Clear();

            foreach (var exception in exceptionOptions)
            {
                string exName = null;
                exName = exception.Path?.FirstOrDefault()?.Names?.FirstOrDefault();

                if (exName != null && exception.BreakMode == ExceptionBreakMode.Always)
                {
                    this.m_Catchpoints.Add(this.m_Session.Breakpoints.AddCatchpoint(exName));
                }
            }
            return new SetExceptionBreakpointsResponse();
        }

        protected override SetBreakpointsResponse HandleSetBreakpointsRequest(SetBreakpointsArguments arguments)
        {
            this.ConsoleLog("setBraekpoints...");
            throw new ProtocolException("setBreakpoints not implemented");
            /*
            string path = null;

            if (arguments.source != null)
            {
                var p = (string)arguments.source.path;
                if (p != null && p.Trim().Length > 0)
                {
                    path = p;
                }
            }

            if (path == null)
            {
                SendErrorResponse(response, 3010, "setBreakpoints: property 'source' is empty or misformed", null, false, true);
                return;
            }

            if (!HasMonoExtension(path))
            {
                // we only support breakpoints in files mono can handle
                SendResponse(response, new SetBreakpointsResponseBody());
                return;
            }

            SourceBreakpoint[] newBreakpoints = getBreakpoints(arguments, "breakpoints");
            bool sourceModified = (bool)arguments.sourceModified;
            var lines = newBreakpoints.Select(bp => bp.line);

            Dictionary<int, Breakpoint> dictionary = null;
            if (m_Breakpoints.ContainsKey(path))
            {
                dictionary = m_Breakpoints[path];
                var keys = new int[dictionary.Keys.Count];
                dictionary.Keys.CopyTo(keys, 0);
                foreach (var line in keys)
                {
                    if (!lines.Contains(line) || sourceModified)
                    {
                        var breakpoint = dictionary[line];
                        m_Session.Breakpoints.Remove(breakpoint);
                        dictionary.Remove(line);
                    }
                }
            }
            else
            {
                dictionary = new Dictionary<int, Breakpoint>();
                m_Breakpoints[path] = dictionary;
            }

            var responseBreakpoints = new List<VSCodeDebug.Breakpoint>();
            foreach (var breakpoint in newBreakpoints)
            {
                if (!dictionary.ContainsKey(breakpoint.line))
                {
                    try
                    {
                        var bp = m_Session.Breakpoints.Add(path, breakpoint.line);
                        bp.ConditionExpression = breakpoint.condition;
                        if (!string.IsNullOrEmpty(breakpoint.logMessage))
                        {
                            bp.HitAction = HitAction.PrintExpression;
                            bp.TraceExpression = breakpoint.logMessage;
                        }
                        dictionary[breakpoint.line] = bp;
                        responseBreakpoints.Add(new VSCodeDebug.Breakpoint(true, breakpoint.line, breakpoint.column, breakpoint.logMessage));
                    }
                    catch (Exception e)
                    {
                        Log.Write(e.StackTrace);
                        SendErrorResponse(response, 3011, "setBreakpoints: " + e.Message, null, false, true);
                        responseBreakpoints.Add(new VSCodeDebug.Breakpoint(false, breakpoint.line, breakpoint.column, e.Message));
                    }
                }
                else
                {
                    dictionary[breakpoint.line].ConditionExpression = breakpoint.condition;
                    responseBreakpoints.Add(new VSCodeDebug.Breakpoint(true, breakpoint.line, breakpoint.column, breakpoint.logMessage));
                }
            }

            SendResponse(response, new SetBreakpointsResponseBody(responseBreakpoints));
            */
        }

        protected override StackTraceResponse HandleStackTraceRequest(StackTraceArguments arguments)
        {
            this.ConsoleLog("stackTrace...");
            throw new ProtocolException("stackTrace not implemented");
            /*
            Log.Write($"UnityDebug: StackTrace: {response} ; {arguments}");
            int maxLevels = GetInt(arguments, "levels", 10);
            int startFrame = GetInt(arguments, "startFrame", 0);
            int threadReference = GetInt(arguments, "threadId", 0);

            WaitForSuspend();

            ThreadInfo thread = DebuggerActiveThread();
            if (thread.Id != threadReference)
            {
                // Console.Error.WriteLine("stackTrace: unexpected: active thread should be the one requested");
                thread = FindThread(threadReference);
                if (thread != null)
                {
                    thread.SetActive();
                }
            }

            var stackFrames = new List<VSCodeDebug.StackFrame>();
            var totalFrames = 0;

            var bt = thread.Backtrace;
            if (bt != null && bt.FrameCount >= 0)
            {
                totalFrames = bt.FrameCount;

                for (var i = startFrame; i < Math.Min(totalFrames, startFrame + maxLevels); i++)
                {
                    var frame = bt.GetFrame(i);

                    string path = frame.SourceLocation.FileName;

                    var hint = "subtle";
                    Source source = null;
                    if (!string.IsNullOrEmpty(path))
                    {
                        string sourceName = Path.GetFileName(path);
                        if (!string.IsNullOrEmpty(sourceName))
                        {
                            if (File.Exists(path))
                            {
                                source = new Source(sourceName, ConvertDebuggerPathToClient(path), 0, "normal");
                                hint = "normal";
                            }
                            else
                            {
                                source = new Source(sourceName, null, 1000, "deemphasize");
                            }
                        }
                    }

                    var frameHandle = m_FrameHandles.Create(frame);
                    string name = frame.SourceLocation.MethodName;
                    int line = frame.SourceLocation.Line;
                    stackFrames.Add(new VSCodeDebug.StackFrame(frameHandle, name, source, ConvertDebuggerLineToClient(line), 0, hint));
                }
            }

            SendResponse(response, new StackTraceResponseBody(stackFrames, totalFrames));
            */
        }

        ThreadInfo DebuggerActiveThread()
        {
            lock (m_Lock)
            {
                return m_Session?.ActiveThread;
            }
        }

        /*
        public override void Source(Response response, dynamic arguments)
        {
            SendErrorResponse(response, 1020, "No source available");
        }
        */

        protected override ScopesResponse HandleScopesRequest(ScopesArguments arguments)
        {
            var frame = m_FrameHandles.Get(arguments.FrameId, null);

            var scopes = new List<Scope>();

            if (frame.Index == 0 && m_Exception != null)
            {
                scopes.Add(new Scope("Exception", m_VariableHandles.Create(new[] { m_Exception }), false));
            }

            var locals = new[] { frame.GetThisReference() }.Concat(frame.GetParameters()).Concat(frame.GetLocalVariables()).Where(x => x != null).ToArray();
            if (locals.Length > 0)
            {
                scopes.Add(new Scope("Local", m_VariableHandles.Create(locals), false));
            }

            return new ScopesResponse(scopes);
        }

        protected override VariablesResponse HandleVariablesRequest(VariablesArguments arguments)
        {
            int reference = arguments.VariablesReference;
            /*
            if (reference == -1)
            {
                SendErrorResponse(response, 3009, "variables: property 'variablesReference' is missing", null, false, true);
                return;
            }
            */

            WaitForSuspend();
            var variables = new List<Variable>();

            // TODO: implement ranged query

            if (m_VariableHandles.TryGet(reference, out var children))
            {
                if (children != null && children.Length > 0)
                {
                    if (children.Length > MAX_CHILDREN)
                    {
                        children = children.Take(MAX_CHILDREN).ToArray();
                    }

                    if (children.Length < 20)
                    {
                        // Wait for all values at once.
                        WaitHandle.WaitAll(children.Select(x => x.WaitHandle).ToArray());
                        variables.AddRange(from v in children where !v.IsError select CreateVariable(v));
                    }
                    else
                    {
                        foreach (var v in children)
                        {
                            if (v.IsError)
                                continue;
                            v.WaitHandle.WaitOne();
                            variables.Add(CreateVariable(v));
                        }
                    }
                }
            }

            return new VariablesResponse(variables);
        }

        protected override ThreadsResponse HandleThreadsRequest(ThreadsArguments arguments)
        {
            var threads = new List<DapThread>();
            var process = m_ActiveProcess;
            if (process != null)
            {
                Dictionary<int, DapThread> d;
                lock (m_SeenThreads)
                {
                    d = new Dictionary<int, DapThread>(m_SeenThreads);
                }

                foreach (var t in process.GetThreads())
                {
                    int tid = (int)t.Id;
                    d[tid] = new DapThread(tid, t.Name);
                }

                threads = d.Values.ToList();
            }

            return new ThreadsResponse(threads);
        }

        protected override EvaluateResponse HandleEvaluateRequest(EvaluateArguments arguments)
        {
            //SendErrorResponse(response, 3014, "Evaluate request failed ({_reason}).", new { _reason = error });
            ProtocolException evaluationError(string error) {
                return new ProtocolException("eval", new Message(3014, "Evaluate request failed ({_reason}).") {
                    Variables = new Dictionary<string, object>() { { "_reason", error }},
                });
            };

            var expression = arguments.Expression;
            var frameId = arguments.FrameId ?? 0;

            if (expression == null)
            {
                throw evaluationError("expression missing");
            }

            var frame = m_FrameHandles.Get(frameId, null);
            if (frame == null)
            {
                throw evaluationError("no active stackframe");
            }

            if (!frame.ValidateExpression(expression))
            {
                throw evaluationError("invalid expression");
            }

            var evaluationOptions = m_DebuggerSessionOptions.EvaluationOptions.Clone();
            evaluationOptions.EllipsizeStrings = false;
            evaluationOptions.AllowMethodEvaluation = true;
            var val = frame.GetExpressionValue(expression, evaluationOptions);
            val.WaitHandle.WaitOne();

            var flags = val.Flags;
            if (flags.HasFlag(ObjectValueFlags.Error) || flags.HasFlag(ObjectValueFlags.NotSupported))
            {
                string error = val.DisplayValue;
                if (error.IndexOf("reference not available in the current evaluation context") > 0)
                {
                    error = "not available";
                }

                throw evaluationError(error);
            }

            if (flags.HasFlag(ObjectValueFlags.Unknown))
            {
                throw evaluationError("invalid expression");
            }

            if (flags.HasFlag(ObjectValueFlags.Object) && flags.HasFlag(ObjectValueFlags.Namespace))
            {
                throw evaluationError("not available");
            }

            int handle = 0;
            if (val.HasChildren)
            {
                handle = m_VariableHandles.Create(val.GetAllChildren());
            }

            return new EvaluateResponse(val.DisplayValue, handle);
        }

        /*
        void SendError(Response response, string error)
        {
            SendErrorResponse(response, 3014, "Evaluate request failed ({_reason}).", new { _reason = error });
        }
        /

        //---- private ------------------------------------------

/*
        void SendOutput(string category, string data)
        {
            if (!string.IsNullOrEmpty(data))
            {
                if (data[data.Length - 1] != '\n')
                {
                    data += '\n';
                }

                SendEvent(new OutputEvent(category, data));
            }
        }
        */

        private void ConsoleLog(string message)
        {
            this.Protocol.SendEvent(new OutputEvent(message) { Category = OutputEvent.CategoryValue.Console });
        }

        /*
        void Terminate(string reason)
        {
            if (!m_Terminated)
            {
                SendEvent(new TerminatedEvent());
                m_Terminated = true;
            }
        }
        */

        ThreadInfo FindThread(int threadReference)
        {
            if (m_ActiveProcess != null)
            {
                foreach (var t in m_ActiveProcess.GetThreads())
                {
                    if (t.Id == threadReference)
                    {
                        return t;
                    }
                }
            }

            return null;
        }

        void Stopped()
        {
            m_Exception = null;
            m_VariableHandles.Reset();
            m_FrameHandles.Reset();
        }

        /*private Variable CreateVariable(ObjectValue v)
        {
            var pname = String.Format("{0} {1}", v.TypeName, v.Name);
            return new Variable(pname, v.DisplayValue, v.HasChildren ? _variableHandles.Create(v.GetAllChildren()) : 0);
        }*/

        Variable CreateVariable(ObjectValue v)
        {
            var dv = v.DisplayValue;
            if (dv.Length > 1 && dv[0] == '{' && dv[dv.Length - 1] == '}')
            {
                dv = dv.Substring(1, dv.Length - 2);
            }

            //return new Variable(v.Name, dv, v.TypeName, v.HasChildren ? m_VariableHandles.Create(v.GetAllChildren()) : 0);
            return new Variable(v.Name, dv, v.HasChildren ? this.m_VariableHandles.Create(v.GetAllChildren()) : 0) {
                Type = v.TypeName,
            };
        }

        Backtrace DebuggerActiveBacktrace()
        {
            var thr = DebuggerActiveThread();
            return thr == null ? null : thr.Backtrace;
        }

        ExceptionInfo DebuggerActiveException()
        {
            var bt = DebuggerActiveBacktrace();
            return bt?.GetFrame(0).GetException();
        }

        bool HasMonoExtension(string path)
        {
            return MONO_EXTENSIONS.Any(path.EndsWith);
        }

        static int GetInt(dynamic container, string propertyName, int dflt = 0)
        {
            try
            {
                return (int)container[propertyName];
            }
            catch (Exception)
            {
                // ignore and return default value
            }

            return dflt;
        }

        static string GetString(dynamic args, string property, string dflt = null)
        {
            var s = (string)args[property];
            if (s == null)
            {
                return dflt;
            }

            s = s.Trim();
            if (s.Length == 0)
            {
                return dflt;
            }

            return s;
        }

        static SourceBreakpoint[] getBreakpoints(dynamic args, string property)
        {
            JArray jsonBreakpoints = args[property];
            var breakpoints = jsonBreakpoints.ToObject<SourceBreakpoint[]>();
            return breakpoints ?? new SourceBreakpoint[0];
        }

        void DebuggerKill()
        {
            lock (m_Lock)
            {
                if (m_Session != null)
                {
                    m_DebuggeeExecuting = true;

                    if (!m_Session.HasExited)
                        m_Session.Exit();

                    m_Session.Dispose();
                    m_Session = null;
                }
            }
        }

        void WaitForSuspend()
        {
            if (!m_DebuggeeExecuting) return;

            m_ResumeEvent.WaitOne();
            m_DebuggeeExecuting = false;
        }
    }
}
