#!/usr/bin/env python
# -*- coding: utf-8 -*-

from Tkinter import *
import hashlib
import time
import threading
import onefunctime as functime
from bcc import BPF
from bcc.utils import printb


from multiprocessing import Process
import signal, os
from time import sleep

import matplotlib.pyplot as plt



OUT_PUT_NUM = 0
listx =[]
listy =[]
j=0
a=0
def runbpf(self, name, sym):
 # print("nanananana %s"%name)
 # print("lalalalala %s"%sym)
  bpf_source = """
  #include <linux/sched.h>
  struct data_t {
    u32 pid;
    u64 ts;
    char comm[TASK_COMM_LEN];
  };
  BPF_PERF_OUTPUT(events);
  BPF_PERF_OUTPUT(event2);

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

    struct data_t data = {};

    data.pid = bpf_get_current_pid_tgid();
    data.ts = duration_ns;
    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    events.perf_submit(ctx, &data, sizeof(data));
    event2.perf_submit(ctx, &data, sizeof(data));


    u32 lat = 0;
    u32 cnt = 1;
    u64 *sum = avg.lookup(&lat);
    if (sum) lock_xadd(sum, duration_ns);
    u64 *cnts = avg.lookup(&cnt);
    if (cnts) lock_xadd(cnts, 1);

    #bpf_trace_printk("Function: blink::V8ScriptRunner::CompileAndRunScript call duration: %d us\\n", duration_ns/1000);
    return 0;
  }
  """


  print("--")
  #bpf_source += bpf_source1
  bpf = BPF(text = bpf_source)
  bpf.attach_uprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE", fn_name = "trace_start_time")
  bpf.attach_uretprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE", fn_name = "print_duration")
  #bpf.attach_uprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libcontent.so", sym = "_ZThn120_N7content15WebContentsImpl19RenderWidgetCreatedEPNS_20RenderWidgetHostImplE", fn_name = "trace_start_time")
  #bpf.attach_uretprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libcontent.so", sym = "_ZThn120_N7content15WebContentsImpl19RenderWidgetCreatedEPNS_20RenderWidgetHostImplE", fn_name = "print_duration")
  #bpf.attach_uprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink19InspectorTaskRunner19isolate_task_runnerEv", fn_name = "trace_start_time")
  #bpf.attach_uretprobe(name =  "/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so", sym = "_ZN5blink19InspectorTaskRunner19isolate_task_runnerEv", fn_name = "print_duration")
  
  #bpf.attach_uprobe(name = name , sym = sym, fn_name = "trace_start_time")
  #bpf.attach_uretprobe(name =  name, sym = sym, fn_name = "print_duration")
  #_ZThn120_N7content15WebContentsImpl19RenderWidgetCreatedEPNS_20RenderWidgetHostImplE

  #_ZN5blink13ClassicScript23RunScriptAndReturnValueEPNS_14LocalDOMWindowENS_19ExecuteScriptPolicyE
  #bpf.trace_print()
  #_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE
  #_ZN5blink21LoaderFactoryForFrame21CreateCodeCacheLoaderEv
  #_ZN5blink5probe13ExecuteScriptD1Ev
  #_ZN2v814ScriptCompiler26CreateCodeCacheForFunctionENS_5LocalINS_8FunctionEEE
  

# header
  print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "MESSAGE"))

# process event

  #X轴，Y轴数据
  #plt.ion()#开始交互模式
  def printa(cpu,data,size):
    print(cpu,data,size)
  def print_event(cpu, data, size):
    #global 
    global a,OUT_PUT_NUM

    event = bpf["events"].event(data)
    time_s = event.ts/1000

    if OUT_PUT_NUM <= 12:
        self.result_data_Text.insert(END,"pid = %-6d , latency: %-10ld us, comm: %-16s\n" %(event.pid, time_s, event.comm))
        OUT_PUT_NUM += 1
    else: 
        self.result_data_Text.delete(1.0,END)
        self.result_data_Text.insert(1.0,"pid = %-6d , latency: %-10ld us, comm: %-16s\n" %(event.pid, time_s, event.comm))
        OUT_PUT_NUM = 0 

    listx.append(a)
    listy.append(time_s)
    plt.plot(listx,listy,"b--",linewidth=1)   #在当前绘图对象绘图（X轴，Y轴，蓝色虚线，线宽度）
    plt.xlabel("Time(s)") #X轴标签
    plt.ylabel("latency")  #Y轴标签
    plt.title("functionlatency") #图标题
    #plt.show()  #显示图
    print listx
    print listy
    a = a + 1
    plt.pause(0.1)
    # loop with callback to print_event
  bpf["events"].open_perf_buffer(print_event)
  bpf["event2"].open_perf_buffer(printa)
  while 1:
    try:
        bpf.perf_buffer_poll()
    except KeyboardInterrupt:
        exit()
'''

  while(1):
    
            global OUT_PUT_NUM

            time.sleep(1);
            total  = bpf['avg'][0].value
            counts = bpf['avg'][1].value
            if counts > 0:
                avg = total/counts
                if OUT_PUT_NUM <= 7:
                    self.result_data_Text.insert(END,"avg = %ld us, total: %ld us, count: %ld\n" %(total/counts, total, counts))
                    OUT_PUT_NUM = OUT_PUT_NUM+1
                else:
                    self.result_data_Text.delete(1.0,2.0)
                    self.result_data_Text.insert(END,"avg = %ld us, total: %ld us, count: %ld\n" %(total/counts, total, counts))
                    OUT_PUT_NUM = 0

        #except:

  
  listx =[]
  listy =[]
  j=0
  a=0
  #X轴，Y轴数据
  plt.ion()#开始交互模式

  while 1:
    global OUT_PUT_NUM
    total  = bpf['avg'][0].value
    counts = bpf['avg'][1].value
    if counts > 0:
        avg = total/counts
        if OUT_PUT_NUM <= 12:
            self.result_data_Text.insert(END,"avg = %ld us, total: %ld us, count: %ld\n" %(total/counts, total, counts))
            OUT_PUT_NUM = OUT_PUT_NUM+1
            listx.append(a)
            listy.append(avg)
            plt.plot(listx,listy,"b--",linewidth=1)   #在当前绘图对象绘图（X轴，Y轴，蓝色虚线，线宽度）
            plt.xlabel("Time(s)") #X轴标签
            plt.ylabel("Avg")  #Y轴标签
            plt.title("functionlatency") #图标题
            #plt.show()  #显示图
            print listx
            print listy
            a = a + 1
            plt.pause(1)
        else:
            self.result_data_Text.delete(1.0,END)
            self.result_data_Text.insert(END,"avg = %ld us, total: %ld us, count: %ld\n" %(total/counts, total, counts))
            OUT_PUT_NUM = 0
'''

#/home/bytedance/graduation_project/chromium/src/out/Default/out/Debug/libblink_core.so
#_ZN5blink14V8ScriptRunner17RunCompiledScriptEPN2v87IsolateENS1_5LocalINS1_6ScriptEEEPNS_16ExecutionContextE
#def worker(arg):
#    runbpf()



global process1

def runbpfprocess(self,name,sym):
  #process1=Process(target=runbpf,kwargs={'self':self,'name':name,'sym':sym})
  #process1.start()
  t1 = threading.Thread(target=runbpf,kwargs={'self':self,'name':name,'sym':sym})
  t1.start()
  #runbpf(self,name,sym)







LOG_LINE_NUM = 0

class MY_GUI():
    def __init__(self,init_window_name):
        self.init_window_name = init_window_name


    #设置窗口
    def set_init_window(self):
        self.init_window_name.title("Chromium性能监控平台")           #窗口名
        #self.init_window_name.geometry('320x160+10+10')                         #290 160为窗口大小，+10 +10 定义窗口弹出时的默认展示位置
        self.init_window_name.geometry('1068x681+10+10')
        #self.init_window_name["bg"] = "pink"                                    #窗口背景色，其他背景色见：blog.csdn.net/chl0000/article/details/7657887
        #self.init_window_name.attributes("-alpha",0.9)                          #虚化，值越小虚化程度越高
        #标签
        self.init_data_label_dir = Label(self.init_window_name, text="符号位置")
        #self.init_data_label_dir.grid(row=0)
        self.init_data_label_dir.pack()

        self.init_data_dir_Text = Entry(self.init_window_name, width=70)  #name录入框
        #self.init_data_dir_Text.grid(row=0, column=1)
        self.init_data_dir_Text.pack()

        self.init_data_label_func = Label(self.init_window_name, text="待监测函数符号")
        #self.init_data_label_func.grid(row=1)
        self.init_data_label_func.pack()

        self.init_data_func_Text = Entry(self.init_window_name, width=70)  #sym录入框
        #self.init_data_func_Text.grid(row=1, column=1)
        self.init_data_func_Text.pack()

        #按钮
        self.str_trans_to_md5_button = Button(self.init_window_name, text="开始监测", bg="lightblue", width=10,command=self.runpro)  # 调用内部方法  加()为直接调用
        #self.str_trans_to_md5_button.grid(row=1, column=2)
        self.str_trans_to_md5_button.pack()

        self.result_data_label = Label(self.init_window_name, text="输出结果")
        #self.result_data_label.grid(row=2, column=0)
        self.result_data_label.pack()

        self.result_data_Text = Text(self.init_window_name, width=70, height=20)  #处理结果展示
        #self.result_data_Text.grid(row=3, column=0, rowspan=15, columnspan=10)
        self.result_data_Text.pack()

        self.log_label = Label(self.init_window_name, text="日志")
        #self.log_label.grid(row=21, column=0)
        self.log_label.pack()
        #文本框

        self.log_data_Text = Text(self.init_window_name, width=70, height=9)  # 日志框
        #self.log_data_Text.grid(row=22, column=0, columnspan=5)
        self.log_data_Text.pack()


    #功能函数
    def runpro(self):
        #src = self.init_data_Text.get(1.0,END).strip().replace("\n","").encode()
        name = self.init_data_dir_Text.get()
        print(name)
        sym = self.init_data_func_Text.get()
        print(sym)

        #try:
        self.write_log_to_Text("INFO:监测当前函数 success")
        runbpfprocess(self,name,sym)
         #except:
        #    self.result_data_Text.delete(1.0,END)
        #    self.result_data_Text.insert(1.0,"监测当前函数 failed")



    #获取当前时间
    def get_current_time(self):
        current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
        return current_time


    #日志动态打印
    def write_log_to_Text(self,logmsg):
        global LOG_LINE_NUM
        current_time = self.get_current_time()
        logmsg_in = str(current_time) +" " + str(logmsg) + "\n"      #换行
        if LOG_LINE_NUM <= 7:
            self.log_data_Text.insert(END, logmsg_in)
            LOG_LINE_NUM = LOG_LINE_NUM + 1
        else:
            self.log_data_Text.delete(1.0,2.0)
            self.log_data_Text.insert(END, logmsg_in)


def gui_start():
    init_window = Tk()              #实例化出一个父窗口
    ZMJ_PORTAL = MY_GUI(init_window)
    # 设置根窗口默认属性
    ZMJ_PORTAL.set_init_window()

    init_window.mainloop()          #父窗口进入事件循环，可以理解为保持窗口运行，否则界面不展示





gui_start()
