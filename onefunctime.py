#!/usr/bin/python
from bcc import BPF

import Tkinter as tk  
import threading
from multiprocessing import Process
import signal, os
from time import sleep

def runbpf(self, name, sym):
 # print("nanananana %s"%name)
 # print("lalalalala %s"%sym)
  bpf_source = """
  BPF_HASH(cache, u64, u64);
  BPF_ARRAY(avg, u64, 2);
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
    cache.delete(&funid);

    u32 lat = 0;
    u32 cnt = 1;
    u64 *sum = avg.lookup(&lat);
    if (sum) lock_xadd(sum, duration_ns);
    u64 *cnts = avg.lookup(&cnt);
    if (cnts) lock_xadd(cnts, 1);

    bpf_trace_printk("Function: blink::V8ScriptRunner::CompileAndRunScript call duration: %d us\\n", duration_ns/1000);
    return 0;
  }
  """


  print("--")
  #bpf_source += bpf_source1
  bpf = BPF(text = bpf_source)
  bpf.attach_uprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE", fn_name = "trace_start_time")
  bpf.attach_uretprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE", fn_name = "print_duration")
  #bpf.attach_uprobe(name = name , sym = sym, fn_name = "trace_start_time")
  #bpf.attach_uretprobe(name =  name, sym = sym, fn_name = "print_duration")
  
  #bpf.trace_print()
  '''
  while(1):
    sleep(1);
    total  = bpf['avg'][0].value
    counts = bpf['avg'][1].value
    if counts > 0:
      avg = total/counts
      print("\n------------------------avg = %ld us, total: %ld us, count: %ld\n" %(total/counts, total, counts))
'''
#/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so
#_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE
#def worker(arg):
#    runbpf()

global process1

def runbpfprocess(self,name,sym):
  #process1=Process(target=runbpf,kwargs={'name':name,'sym':sym})
  #process1.start()
  t1 = threading.Thread(target=runbpf,kwargs={'self':self,'name':name,'sym':sym})
  t1.start()

def printexit():
  print ("process exit")

def sendexit():
  signal.signal(signal.SIGINT, printexit)
  os.kill(os.getpid(), signal)

'''
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
'''