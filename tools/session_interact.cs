// Loaded by session_interact.ps1 in the selected user's actual desktop session.
using System;
using System.IO;
using System.Text;
using System.Diagnostics;
using System.Threading;
using System.Collections.Generic;
using System.Security.Principal;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;

public static class DropbearInteraction {
    [StructLayout(LayoutKind.Sequential)] struct WtsSession { public int id; public IntPtr station; public int state; }
    [DllImport("wtsapi32.dll")] static extern bool WTSEnumerateSessionsW(IntPtr server, int reserved, int version, out IntPtr sessions, out int count);
    [DllImport("wtsapi32.dll")] static extern bool WTSQuerySessionInformationW(IntPtr server, int id, int kind, out IntPtr value, out int size);
    [DllImport("wtsapi32.dll")] static extern void WTSFreeMemory(IntPtr value);
    public class Session {
        public int session_id; public string username, domain, windows_user, state, station, sid;
        public bool selectable;
    }
    static string WtsText(int id, int kind) {
        IntPtr p; int n;
        if (!WTSQuerySessionInformationW(IntPtr.Zero, id, kind, out p, out n)) return "";
        try { return Marshal.PtrToStringUni(p) ?? ""; } finally { WTSFreeMemory(p); }
    }
    public static Session[] Sessions() {
        IntPtr p; int count;
        if (!WTSEnumerateSessionsW(IntPtr.Zero, 0, 1, out p, out count)) throw new Exception("WTSEnumerateSessions failed");
        var rows = new List<Session>();
        string[] states = {"Active", "Connected", "ConnectQuery", "Shadow", "Disconnected", "Idle", "Listen", "Reset", "Down", "Init"};
        try {
            for (int i=0; i<count; i++) {
                var s=(WtsSession)Marshal.PtrToStructure(IntPtr.Add(p,i*Marshal.SizeOf(typeof(WtsSession))), typeof(WtsSession));
                string user=WtsText(s.id,5), domain=WtsText(s.id,7), name=String.IsNullOrEmpty(domain)?user:domain+"\\"+user, sid="";
                if (!String.IsNullOrEmpty(user)) {
                    try { sid=((SecurityIdentifier)new NTAccount(name).Translate(typeof(SecurityIdentifier))).Value; } catch (IdentityNotMappedException) { }
                }
                rows.Add(new Session { session_id=s.id, username=user, domain=domain, windows_user=name,
                    state=s.state>=0 && s.state<states.Length?states[s.state]:s.state.ToString(),
                    station=Marshal.PtrToStringUni(s.station), sid=sid,
                    selectable=s.id>0 && (s.state==0 || s.state==1) && !String.IsNullOrEmpty(user) && !String.IsNullOrEmpty(sid) });
            }
        } finally { WTSFreeMemory(p); }
        return rows.ToArray();
    }

    [DllImport("user32.dll")] static extern IntPtr OpenInputDesktop(uint flags, bool inherit, uint access);
    [DllImport("user32.dll")] static extern bool CloseDesktop(IntPtr desktop);
    [DllImport("user32.dll", CharSet=CharSet.Unicode)] static extern bool GetUserObjectInformationW(IntPtr h,int index,StringBuilder value,int size,out int needed);
    [DllImport("user32.dll")] public static extern IntPtr GetForegroundWindow();
    public static string InputDesktop() {
        IntPtr h=OpenInputDesktop(0,false,1);
        if(h==IntPtr.Zero) throw new Exception("Input desktop unavailable: locked, disconnected or access denied");
        try { int n; var b=new StringBuilder(256); if(!GetUserObjectInformationW(h,2,b,512,out n)) throw new Exception("Cannot read input desktop"); return b.ToString(); }
        finally { CloseDesktop(h); }
    }
    static void RequireDesktop() {
        if(!String.Equals(InputDesktop(),"Default",StringComparison.OrdinalIgnoreCase)) throw new Exception("Only the unlocked Default input desktop is supported");
    }
    [StructLayout(LayoutKind.Sequential)] public struct Rect { public int left,top,right,bottom; }
    public class Window { public string window_id,title,class_name; public int pid; public bool foreground; public Rect bounds; }
    delegate bool EnumWindow(IntPtr h,IntPtr arg);
    [DllImport("user32.dll")] static extern bool EnumWindows(EnumWindow callback,IntPtr arg);
    [DllImport("user32.dll")] static extern bool IsWindowVisible(IntPtr h);
    [DllImport("user32.dll")] static extern bool IsWindow(IntPtr h);
    [DllImport("user32.dll")] static extern uint GetWindowThreadProcessId(IntPtr h,out int pid);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetWindowTextW(IntPtr h,StringBuilder text,int count);
    [DllImport("user32.dll",CharSet=CharSet.Unicode)] static extern int GetClassNameW(IntPtr h,StringBuilder text,int count);
    [DllImport("user32.dll")] static extern bool GetWindowRect(IntPtr h,out Rect bounds);
    [DllImport("user32.dll")] static extern bool SetForegroundWindow(IntPtr h);
    [DllImport("user32.dll")] static extern bool ShowWindowAsync(IntPtr h,int command);
    [DllImport("user32.dll")] static extern bool IsIconic(IntPtr h);
    [DllImport("user32.dll")] static extern int GetSystemMetrics(int index);
    [DllImport("user32.dll")] public static extern bool SetProcessDPIAware();
    public static Window[] Windows() {
        RequireDesktop(); var rows=new List<Window>();
        EnumWindow cb=delegate(IntPtr h,IntPtr ignored) {
            if(!IsWindowVisible(h) || rows.Count>=512) return true;
            int pid; GetWindowThreadProcessId(h,out pid); Rect bounds; GetWindowRect(h,out bounds);
            var title=new StringBuilder(4096); var cls=new StringBuilder(256);
            GetWindowTextW(h,title,title.Capacity); GetClassNameW(h,cls,cls.Capacity);
            rows.Add(new Window {window_id=h.ToInt64().ToString(),title=title.ToString(),class_name=cls.ToString(),pid=pid,bounds=bounds,foreground=h==GetForegroundWindow()});
            return true;
        };
        EnumWindows(cb,IntPtr.Zero); return rows.ToArray();
    }
    static IntPtr CheckWindow(string id) {
        RequireDesktop(); long value;
        if(!Int64.TryParse(id,out value) || value<=0) throw new Exception("window_id must come from windows in this session");
        IntPtr h=new IntPtr(value); int pid;
        if(!IsWindow(h) || !IsWindowVisible(h)) throw new Exception("Window is no longer available");
        GetWindowThreadProcessId(h,out pid);
        if(Process.GetProcessById(pid).SessionId!=Process.GetCurrentProcess().SessionId) throw new Exception("Window belongs to another session");
        return h;
    }
    public static void Focus(string id) {
        IntPtr h=CheckWindow(id);
        if(IsIconic(h)) ShowWindowAsync(h,9);
        if(GetForegroundWindow()!=h) { SetForegroundWindow(h); Thread.Sleep(100); }
        if(GetForegroundWindow()!=h) throw new Exception("Windows refused foreground focus; no input sent");
    }
    [StructLayout(LayoutKind.Sequential)] struct Mouse { public int x,y; public uint data,flags,time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Sequential)] struct Keyboard { public ushort key,scan; public uint flags,time; public UIntPtr extra; }
    [StructLayout(LayoutKind.Explicit)] struct InputUnion { [FieldOffset(0)] public Mouse mouse; [FieldOffset(0)] public Keyboard keyboard; }
    [StructLayout(LayoutKind.Sequential)] struct Input { public uint type; public InputUnion data; }
    [DllImport("user32.dll",SetLastError=true)] static extern uint SendInput(uint count,Input[] inputs,int size);
    [DllImport("user32.dll")] static extern uint MapVirtualKeyW(uint code,uint type);
    static void Send(Input[] events) {
        RequireDesktop();
        if(SendInput((uint)events.Length,events,Marshal.SizeOf(typeof(Input)))!=events.Length)
            throw new Exception("SendInput failed or was partial (desktop changed or UIPI/integrity restriction); input outcome may be partial");
    }
    static Input Key(ushort code, bool up, bool unicode) {
        ushort scan=unicode?code:(ushort)MapVirtualKeyW(code,0);
        if(!unicode && scan==0) throw new Exception("Cannot map key to keyboard scan code");
        bool extended=!unicode && (code==91 || code==92 || (code>=33 && code<=40) || code==45 || code==46);
        return new Input {type=1,data=new InputUnion {keyboard=new Keyboard {key=0,scan=scan,flags=(up?2u:0u)|(unicode?4u:8u)|(extended?1u:0u)}}};
    }
    public static void Text(string id,string text) {
        if(text==null || text.Length>4096) throw new Exception("text is limited to 4096 UTF-16 code units");
        Focus(id);
        foreach(char c in text) {
            if(GetForegroundWindow()!=CheckWindow(id)) throw new Exception("Foreground window changed; input stopped");
            Send(new Input[] {Key(c,false,true),Key(c,true,true)});
        }
    }
    static ushort Code(string key) {
        key=key.ToUpperInvariant();
        if(key.Length==1 && ((key[0]>='A' && key[0]<='Z') || (key[0]>='0' && key[0]<='9'))) return key[0];
        var map=new Dictionary<string,ushort> {{"CTRL",17},{"ALT",18},{"SHIFT",16},{"WIN",91},{"ENTER",13},{"TAB",9},{"ESC",27},{"SPACE",32},{"BACKSPACE",8},{"DELETE",46},{"LEFT",37},{"RIGHT",39},{"UP",38},{"DOWN",40},{"HOME",36},{"END",35},{"PAGEUP",33},{"PAGEDOWN",34}};
        ushort code; if(map.TryGetValue(key,out code)) return code;
        int f; if(key.StartsWith("F") && Int32.TryParse(key.Substring(1),out f) && f>=1 && f<=24) return (ushort)(111+f);
        throw new Exception("Unsupported key name: "+key);
    }
    public static void Keys(string id,string[] keys) {
        if(keys==null || keys.Length<1 || keys.Length>5) throw new Exception("keys must contain one key preceded by optional CTRL/ALT/SHIFT/WIN modifiers");
        var codes=new List<ushort>();
        for(int i=0;i<keys.Length;i++) { ushort c=Code(keys[i]); if(i<keys.Length-1 && c!=16 && c!=17 && c!=18 && c!=91) throw new Exception("Only modifiers may precede the last key"); if(codes.Contains(c)) throw new Exception("Duplicate key"); codes.Add(c); }
        Focus(id); var events=new List<Input>();
        foreach(ushort c in codes) events.Add(Key(c,false,false));
        codes.Reverse(); foreach(ushort c in codes) events.Add(Key(c,true,false));
        // One SendInput batch prevents physical/other injected input interleaving a chord.
        try { Send(events.ToArray()); }
        catch { foreach(ushort c in codes) { try {Send(new Input[] {Key(c,true,false)});}catch{} } throw; }
    }
    public static void Click(string id,int x,int y,string button) {
        IntPtr h=CheckWindow(id); Rect r; GetWindowRect(h,out r);
        if(x<r.left || x>=r.right || y<r.top || y>=r.bottom) throw new Exception("Click is outside the selected window");
        int left=GetSystemMetrics(76),top=GetSystemMetrics(77),width=GetSystemMetrics(78),height=GetSystemMetrics(79);
        if(width<=1 || height<=1 || x<left || x>=left+width || y<top || y>=top+height) throw new Exception("Click is outside the virtual desktop");
        if(button!="left" && button!="right") throw new Exception("button must be left or right");
        Focus(id);
        uint down=button=="right"?8u:2u,up=button=="right"?16u:4u;
        Send(new Input[] {
            new Input {type=0,data=new InputUnion {mouse=new Mouse {x=(int)((long)(x-left)*65535/(width-1)),y=(int)((long)(y-top)*65535/(height-1)),flags=0xC001}}},
            new Input {type=0,data=new InputUnion {mouse=new Mouse {flags=down}}},
            new Input {type=0,data=new InputUnion {mouse=new Mouse {flags=up}}}
        });
    }

    [StructLayout(LayoutKind.Sequential)] struct BasicLimit { public long processTime,jobTime; public uint flags; public UIntPtr min,max; public uint active; public UIntPtr affinity; public uint priority,scheduling; }
    [StructLayout(LayoutKind.Sequential)] struct IoCounters { public ulong a,b,c,d,e,f; }
    [StructLayout(LayoutKind.Sequential)] struct ExtendedLimit { public BasicLimit basic; public IoCounters io; public UIntPtr processMemory,jobMemory,peakProcess,peakJob; }
    [DllImport("kernel32.dll")] static extern IntPtr CreateJobObjectW(IntPtr attributes,string name);
    [DllImport("kernel32.dll")] static extern bool SetInformationJobObject(IntPtr job,int kind,ref ExtendedLimit info,int size);
    [DllImport("kernel32.dll")] static extern bool AssignProcessToJobObject(IntPtr job,IntPtr process);
    [DllImport("kernel32.dll")] static extern bool TerminateJobObject(IntPtr job,uint code);
    [DllImport("kernel32.dll")] static extern bool CloseHandle(IntPtr handle);
    [StructLayout(LayoutKind.Sequential)] struct Security { public int length; public IntPtr descriptor; public int inherit; }
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)] struct Startup {
        public int size; public string reserved,desktop,title; public uint x,y,width,height,charsX,charsY,fill,flags;
        public ushort show,reservedSize; public IntPtr reservedBytes,input,output,error;
    }
    [StructLayout(LayoutKind.Sequential)] struct ProcessInfo { public IntPtr process,thread; public uint pid,tid; }
    [DllImport("kernel32.dll",SetLastError=true)] static extern bool CreatePipe(out IntPtr read,out IntPtr write,ref Security security,uint size);
    [DllImport("kernel32.dll")] static extern bool SetHandleInformation(IntPtr handle,uint mask,uint flags);
    [DllImport("kernel32.dll",CharSet=CharSet.Unicode,SetLastError=true)] static extern bool CreateProcessW(string app,StringBuilder command,IntPtr pa,IntPtr ta,bool inherit,uint flags,IntPtr environment,string cwd,ref Startup startup,out ProcessInfo process);
    [DllImport("kernel32.dll")] static extern uint ResumeThread(IntPtr thread);
    [DllImport("kernel32.dll")] static extern bool TerminateProcess(IntPtr process,uint code);
    [DllImport("kernel32.dll")] static extern uint WaitForSingleObject(IntPtr handle,uint milliseconds);
    [DllImport("kernel32.dll")] static extern bool GetExitCodeProcess(IntPtr process,out uint code);
    public class Execution { public int exit_code; public string stdout_base64,stderr_base64; public bool timed_out,output_limit_exceeded; }
    class Capture {
        public int bytes,overflow; public IntPtr job;
        public void Read(Stream input,MemoryStream output) {
            byte[] b=new byte[8192]; int n;
            try { while((n=input.Read(b,0,b.Length))>0) {
                if(Interlocked.Add(ref bytes,n)<=1048576) output.Write(b,0,n);
                else { Interlocked.Exchange(ref overflow,1); TerminateJobObject(job,125); }
            } } catch(IOException) { } catch(ObjectDisposedException) { }
        }
    }
    static string Quote(string value) {
        if(value==null || value.IndexOf('\0')>=0) throw new Exception("Arguments cannot contain NUL");
        if(value.Length>0 && value.IndexOfAny(new char[] {' ', '\t', '\n', '\r', '"'})<0) return value;
        var s=new StringBuilder("\""); int slashes=0;
        foreach(char c in value) { if(c=='\\') {slashes++;continue;} if(c=='\"') s.Append('\\',slashes*2+1); else s.Append('\\',slashes); s.Append(c);slashes=0; }
        s.Append('\\',slashes*2); return s.Append('"').ToString();
    }
    public static Execution Run(string program,string[] args,string cwd,Dictionary<string,string> environment,byte[] input,int timeoutMs) {
        var argv=new List<string>(); foreach(string arg in args) argv.Add(Quote(arg));
        var command=new StringBuilder(Quote(program)+" "+String.Join(" ",argv.ToArray()));
        if(command.Length>=32767) throw new Exception("Windows command line exceeds 32766 characters");
        cwd=String.IsNullOrEmpty(cwd)?Environment.GetFolderPath(Environment.SpecialFolder.UserProfile):cwd;
        var variables=new SortedDictionary<string,string>(StringComparer.OrdinalIgnoreCase);
        foreach(System.Collections.DictionaryEntry item in Environment.GetEnvironmentVariables()) variables[(string)item.Key]=(string)item.Value;
        foreach(var item in environment) variables[item.Key]=item.Value;
        var block=new StringBuilder(); foreach(var item in variables) block.Append(item.Key).Append('=').Append(item.Value).Append('\0'); block.Append('\0');
        IntPtr job=CreateJobObjectW(IntPtr.Zero,null);
        if(job==IntPtr.Zero) throw new Exception("Cannot create command job");
        var limits=new ExtendedLimit(); limits.basic.flags=0x2000;
        Thread output=null,error=null,writer=null;
        IntPtr childIn=IntPtr.Zero,parentIn=IntPtr.Zero,parentOut=IntPtr.Zero,childOut=IntPtr.Zero,parentErr=IntPtr.Zero,childErr=IntPtr.Zero,envBlock=IntPtr.Zero;
        FileStream inputStream=null,outputStream=null,errorStream=null;
        var process=new ProcessInfo(); bool resumed=false;
        try {
            if(!SetInformationJobObject(job,9,ref limits,Marshal.SizeOf(typeof(ExtendedLimit)))) throw new Exception("Cannot configure command job");
            var security=new Security {length=Marshal.SizeOf(typeof(Security)),inherit=1};
            if(!CreatePipe(out childIn,out parentIn,ref security,0) || !CreatePipe(out parentOut,out childOut,ref security,0) || !CreatePipe(out parentErr,out childErr,ref security,0) ||
                !SetHandleInformation(parentIn,1,0) || !SetHandleInformation(parentOut,1,0) || !SetHandleInformation(parentErr,1,0)) throw new Exception("Cannot create command pipes");
            var startup=new Startup {size=Marshal.SizeOf(typeof(Startup)),flags=0x100,input=childIn,output=childOut,error=childErr};
            envBlock=Marshal.StringToHGlobalUni(block.ToString());
            if(!CreateProcessW(program,command,IntPtr.Zero,IntPtr.Zero,true,0x08000404,envBlock,cwd,ref startup,out process)) throw new Exception("CreateProcess failed: "+Marshal.GetLastWin32Error());
            CloseHandle(childIn);childIn=IntPtr.Zero;CloseHandle(childOut);childOut=IntPtr.Zero;CloseHandle(childErr);childErr=IntPtr.Zero;
            if(!AssignProcessToJobObject(job,process.process)) throw new Exception("Cannot contain session command in a job");
            inputStream=new FileStream(new SafeFileHandle(parentIn,true),FileAccess.Write);parentIn=IntPtr.Zero;
            outputStream=new FileStream(new SafeFileHandle(parentOut,true),FileAccess.Read);parentOut=IntPtr.Zero;
            errorStream=new FileStream(new SafeFileHandle(parentErr,true),FileAccess.Read);parentErr=IntPtr.Zero;
            var capture=new Capture {job=job}; var stdout=new MemoryStream(); var stderr=new MemoryStream();
            output=new Thread(delegate() {capture.Read(outputStream,stdout);}); output.IsBackground=true; output.Start();
            error=new Thread(delegate() {capture.Read(errorStream,stderr);}); error.IsBackground=true; error.Start();
            writer=new Thread(delegate() {try {inputStream.Write(input,0,input.Length);inputStream.Close();}catch(IOException){}catch(ObjectDisposedException){}}); writer.IsBackground=true; writer.Start();
            if(ResumeThread(process.thread)==0xFFFFFFFF) throw new Exception("Cannot resume command");
            resumed=true;
            uint waited=WaitForSingleObject(process.process,(uint)timeoutMs);
            if(waited!=0 && waited!=258) throw new Exception("Cannot wait for command process");
            bool timeout=waited==258;
            TerminateJobObject(job,timeout?124u:0u);
            if(WaitForSingleObject(process.process,2000)!=0) throw new Exception("Command did not stop after job termination");
            uint exitCode; if(!GetExitCodeProcess(process.process,out exitCode)) throw new Exception("Cannot read command exit code");
            if(!output.Join(3000) || !error.Join(3000) || !writer.Join(3000)) throw new Exception("Command streams did not finish after job termination");
            return new Execution {exit_code=timeout?-1:unchecked((int)exitCode),timed_out=timeout,output_limit_exceeded=capture.overflow!=0,stdout_base64=Convert.ToBase64String(stdout.ToArray()),stderr_base64=Convert.ToBase64String(stderr.ToArray())};
        } finally {
            if(process.process!=IntPtr.Zero && !resumed) TerminateProcess(process.process,125);
            CloseHandle(job);
            foreach(IntPtr handle in new IntPtr[] {childIn,parentIn,parentOut,childOut,parentErr,childErr,process.thread,process.process}) if(handle!=IntPtr.Zero) CloseHandle(handle);
            if(envBlock!=IntPtr.Zero) Marshal.FreeHGlobal(envBlock);
            if(inputStream!=null) inputStream.Dispose();if(outputStream!=null) outputStream.Dispose();if(errorStream!=null) errorStream.Dispose();
        }
    }
}
