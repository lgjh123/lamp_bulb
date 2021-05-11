#!/usr/bin/python
from bcc import BPF
import time
import Tkinter as tk  
import threading
from multiprocessing import Process
import signal, os

def runbpf():
  bpf_source = """
  BPF_HASH(cache, u64, u64);
  int trace_start_time(struct pt_regs *ctx) {
    //u64 pid = bpf_get_current_pid_tgid();
    u64 funid = 1;
    u64 start_time_ns = bpf_ktime_get_ns();
    cache.update(&funid, &start_time_ns);
    return 0;
  }
  """

  bpf_source += """
  int print_duration(struct pt_regs *ctx) {
    //u64 pid = bpf_get_current_pid_tgid();
    u64 funid = 1;
    u64 *start_time_ns = cache.lookup(&funid);
    if (start_time_ns == 0) {
      return 0;
    }
    u64 duration_ns = bpf_ktime_get_ns() - *start_time_ns;
    bpf_trace_printk("Function: blink::V8ScriptRunner::CompileAndRunScript call duration: %d ms\\n", duration_ns/1000000);
    return 0;
  }
  """

  bpf_source1 = """
  //BPF_HASH(cache1, u64, u64);
  int trace_start_time1(struct pt_regs *ctx) {
    //u64 pid = bpf_get_current_pid_tgid();
    u64 funid = 2;
    u64 start_time_ns = bpf_ktime_get_ns();
    cache.update(&funid, &start_time_ns);
    return 0;
  }
  """

  bpf_source1 += """
  int print_duration1(struct pt_regs *ctx) {
    //u64 pid = bpf_get_current_pid_tgid();
    u64 funid = 2;
    u64 *start_time_ns = cache.lookup(&funid);
    if (start_time_ns == 0) {
      return 0;
    }
    u64 duration_ns = bpf_ktime_get_ns() - *start_time_ns;
    bpf_trace_printk("Function: CompileScriptOnMainThread call duration: %d us\\n", duration_ns/1000);
    return 0;
  }
  """ 

  print("--")
  bpf_source += bpf_source1
  bpf = BPF(text = bpf_source)
  bpf.attach_uprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE", fn_name = "trace_start_time")
  bpf.attach_uretprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE", fn_name = "print_duration")
  #bpf = BPF(text = bpf_source1)
  bpf.attach_uprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libv8.so", sym = "_ZN2v88internal12_GLOBAL__N_125CompileScriptOnMainThreadENS0_23UnoptimizedCompileFlagsENS0_6HandleINS0_6StringEEERKNS0_8Compiler13ScriptDetailsENS_19ScriptOriginOptionsENS0_11NativesFlagEPNS_9ExtensionEPNS0_7IsolateEPNS0_15IsCompiledScopeE", fn_name = "trace_start_time1")
  bpf.attach_uretprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libv8.so", sym = "_ZN2v88internal12_GLOBAL__N_125CompileScriptOnMainThreadENS0_23UnoptimizedCompileFlagsENS0_6HandleINS0_6StringEEERKNS0_8Compiler13ScriptDetailsENS_19ScriptOriginOptionsENS0_11NativesFlagEPNS_9ExtensionEPNS0_7IsolateEPNS0_15IsCompiledScopeE", fn_name = "print_duration1")
  bpf.trace_print()
#while 1 :
#  time1 = bpf["cache"]
#  time.sleep(1)
#  for k, v in sorted(time1.items()):
#      print( k.value,v.value)  


#print ("-------------------time = %d\n"% time[1].value)
#bpf.trace_print()
def worker(arg):
    runbpf()

global process1

def runbpfprocess():
  process1=Process(target=runbpf)
  process1.start()

def printexit():
  print ("process exit")

def sendexit():
  signal.signal(signal.SIGINT, printexit)
  os.kill(os.getpid(), signal)


window = tk.Tk()

window.title('My Window')

window.geometry('500x300') 
 

e = tk.Entry(window, show = None)
e.pack()

f = tk.Entry(window, show = None)
f.pack()
 
def insert_point(): 
    var = e.get()
    print (var)
    t.insert('insert', var)
def insert_end():   
    var = f.get()
    t.insert('end', var)
 
b1 = tk.Button(window, text='insert point', width=10,
               height=2, command=runbpfprocess)
b1.pack()
b2 = tk.Button(window, text='insert end', width=10,
               height=2, command=sendexit)
b2.pack()
 

t = tk.Text(window, height=3)
t.pack()
 

window.mainloop()