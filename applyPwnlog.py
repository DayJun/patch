from pwn import *
import argparse
import re

class Pwnlog():
    def __init__(self, logfile, binary):
        self.logfile = logfile
        self.binary = binary
        self.elf = ELF(binary, checksec=False)
        self.parsedLog = []
        self.sendDataLog = []
        self.recvDataLog = []
        self.recvedIdx = []
        self.inputFlag = True
        self.currentAddress = 0
        self.printDataFlag = True
        self.notEndFlag = True
        self.parse()

    def parse(self):
        with open(self.logfile, 'rb') as f:
            data = bytearray(f.read())
            end = len(data)
            start = 0
            while start < end:
                i = start
                KV = {}
                if data[i:i+5] == 'read:':
                    KV['type'] = 'read'
                    length = data[i+5]
                    KV['length'] = length
                    if self.elf.arch == 'amd64':
                        KV['address'] = u64(data[i+6:i+14])
                        start += 14+length
                        KV['data'] = data[i+14:i+14+length]
                    elif self.elf.arch == 'i386':
                        KV['address'] = u32(data[i+6:i+10])
                        start += 10+length
                        KV['data'] = data[i+10:i+10+length]
                    
                    self.parsedLog.append(KV)
                    
                elif data[i:i+6] == 'scanf:':
                    KV['type'] = 'scanf'
                    operate = ''
                    i += 6
                    while data[i] != 0:
                        operate += chr(data[i])
                        i += 1
                    KV['operate'] = operate
                    KV['data'] = ''
                    i += 1
                    while data[i] != 0:
                        KV['data'] += data[i]
                        i += 1
                    if self.elf.arch == 'amd64':
                        KV['address'] = u64(data[i+1:i+9])
                        start = i + 9
                    elif self.elf.arch == 'i386':
                        KV['address'] = u32(data[i+1:i+5])
                        start = i + 5
                    self.parsedLog.append(KV)
                    

    def help(self):
        print "---------------------------------"
        print "\thelp --> get help"
        print "\tq --> quit"
        print "\tr --> run until recv"
        print "\tenter --> next step"
        print "\ts --> save the sended data into a group"
        print "\tsr --> save the received data into a group"
        print "\tx [s|r] index start end [u64|u32|u16|u8|int] --> choose received data and log"
        print "\tms sendidx start end recvidx --> modify the sended data"
        print "\tls [debug|info] [idx|or not] -> list saved sended data"
        print "\tlsa [debug|info] -> list all sended data"
        print "\tis index -> insert send info sendlog"
        print "\tsavelog [filename] -> save send log"
        print "\tsave [filename] -> save exp"
        print "\tit -> interactive()"
        print "---------------------------------"


    def printData(self, idx):
        kv = self.parsedLog[idx]
        if kv['type'] != 'scanf':
            log.info('Step \033[;32m%d\033[0m \033[;36m0x%x\033[0m \033[;35m%s(0x%x)\033[0m:' %(idx, kv['address'], kv['type'], kv['length']))
            log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
            log.hexdump(kv['data'])
        else:
            log.info('Step \033[;32m%d\033[0m \033[;36m0x%x\033[0m \033[;35m%s(%s)\033[0m:' %(idx, kv['address'], kv['type'], kv['operate']))
        return kv

    def recvDataTimeout(self, timeout):
        try:
            data = io.recv(0x1000, timeout=timeout)
        except:
            log.failure("EOF")
            return
        if len(data) == 0:
            log.info("No data received")
        else:
            self.inputFlag = True
            log.success("Received data: "+data)
            log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
            log.hexdump(data)
        return data

    def list(self, sa, mode=None, idx=None):
        if sa == 's':
            if len(self.sendDataLog) == 0:
                log.warn("No data")
                return 
            log.success("Saved sended and recved data:")
            if idx == None:
                recvLogidx = 0
                for i in range(len(self.sendDataLog)):
                    print '---------------------------------'
                    data = self.sendDataLog[i]
                    log.success("log send index: \033[;32m%d\033[0m" %(i))
                    log.info("send index: \033[;31m%d\033[0m" %(data['index']))
                    log.info("address: \033[;36m0x%x\033[0m %s" %(data['address'], data['type']))
                    if data['type'] != 'scanf:':
                        if mode == 'debug':
                            log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
                            log.hexdump(data['data'])
                        else:
                            log.info(data['data'])
                    try:
                        if i == self.recvDataLog[recvLogidx]['sendidx']:
                            recvLog = self.recvDataLog[recvLogidx]
                            log.success("recv index: \033[;32m%d\033[0m" %(recvLogidx))
                            recvLogidx += 1
                            log.info('data: '+recvLog['data'])
                            if mode == 'debug':
                                log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
                                log.hexdump(recvLog['data'])
                            log.info("recvuntil: %s" %(recvLog['recvuntil']))
                            log.info("recvlength: \033[;32m%d\033[0m" %(recvLog['recvlength']))
                            log.info("mode: %s" %(recvLog['mode']))
                    except:
                        pass

            else:
                print '---------------------------------'
                try:
                    data = self.sendDataLog[idx]
                except:
                    log.warn("Index too big or small")
                    return 
                log.success("log send index: \033[;32m%d\033[0m" %(idx))
                log.info("send index: \033[;31m%d\033[0m" %(data['index']))
                log.info("address: \033[;36m0x%x\033[0m %s" %(data['address'], data['type']))
                if data['type'] != 'scanf':
                    if mode == 'debug':
                        log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
                        log.hexdump(data['data'])
                    else:
                        log.info(data['data'])
                for recvLogidx in range(len(self.recvDataLog)):
                    if idx == self.recvDataLog[recvLogidx]['sendidx']:
                        recvLog = self.recvDataLog[recvLogidx]
                        log.success("recv index: %d" %(recvLogidx))
                        log.info('data: '+recvLog['data'])
                        if mode == 'debug':
                            log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
                            log.hexdump(recvLog['data'])
                        log.info("recvuntil: %s" %(recvLog['recvuntil']))
                        log.info("recvlength: \033[;32m%d\033[0m" %(recvLog['recvlength']))
                        log.info("mode: %s" %(recvLog['mode']))
                        break
            print '---------------------------------'
        elif sa == 'a':
            for idx in range(len(self.parsedLog)):
                print '---------------------------------'
                data = self.parsedLog[idx]
                log.success("send index: \033[;31m%d\033[0m" %(idx))
                log.info("address: \033[;36m0x%x\033[0m %s" %(data['address'], data['type']))
                if data['type'] != 'scanf':
                    if mode == 'debug':
                        log.info(' index\t\033[;33m00 01 02 03  04 05 06 07  08 09 0a 0b  0c 0d 0e 0f\033[0m')
                        log.hexdump(data['data'])
                    else:
                        log.info(data['data'])
            print '---------------------------------'
        print ''


    def logRecvData(self, data, start, end, mode=None):
        sendidx = len(self.sendDataLog) - 1
        if sendidx == -1:
            log.info("Save sended data first")
            return 
        if sendidx not in self.recvedIdx:
            kv = {}
            kv['data'] = data
            kv['sendidx'] = sendidx
            if mode is None:
                kv['recvuntil'] = data[start:end]
                kv['mode'] = 'recvline'
                kv['recvlength'] = 0
            else:
                kv['recvuntil'] = data[0:start]
                kv['mode'] = mode
                kv['recvlength'] = end - start
            self.recvDataLog.append(kv)
            self.recvedIdx.append(kv['sendidx'])
            log.success('Log recv succeed')
        else:
            log.info("You already have one recv log to Send %d" %(sendidx))

    def modifySavedData(self, si, start, end, ri):
        sendData = self.sendDataLog[si]
        newSendData = sendData[:start]
        newSendData += '[' + str(ri) + ']'
        self.sendDataLog[si] = newSendData
        log.success("Modify succeed")
        self.list('info', si)

    def parseLogData(self, sr, idx, s, e, m):
        try:
            if sr == 's':
                sendData = self.sendDataLog[idx]
            elif sr == 'r':
                sendData = self.recvDataLog[idx]['data']
            else:
                log.warn("No such choice")
                return
        except:
            log.warn("index out of bound")
            return
        data = sendData[s:e]
        if m == 'u64':
            d = u64(data.ljust(8, '\x00'))
            log.success('0x%x %d' %(d, d))
        elif m == 'u32':
            d = u32(data.ljust(4, '\x00'))
            log.success('0x%x %d' %(d, d))
        elif m == 'u16':
            d = u16(data.ljust(2, '\x00'))
            log.success('0x%x %d' %(d, d))
        elif m == 'u8':
            d = u8(data.ljust(1, '\x00'))
            log.success('0x%x %d' %(d, d))
        elif m == 'int':
            d = int(data, 16)
            log.success('0x%x %d' %(d, d))


    def insert(self, idx, sendedData):
        try:
            data = self.parsedLog[idx]
        except:
            log.warn("Index too big or small")
            return 
        insertInto = idx
        if len(self.sendDataLog) >= 2:
            for i in range(len(self.sendDataLog)-1):
                d = self.sendDataLog[i]
                d1 = self.sendDataLog[i+1]
                if d['index'] == idx or d1['index'] == idx:
                    log.warn("Already saved it")
                    break
                if d['index'] < idx and d1['index'] > idx:
                    insertInto = i + 1
                    break
                elif d['index'] < idx and d1['index'] < idx:
                    insertInto = i + 2
                    break
                elif d['index'] > idx and d1['index'] > idx:
                    insertInto = i
                    break
        elif len(self.sendDataLog) == 1:
            d = self.sendDataLog[idx]
            if d['index'] == idx:
                log.warn("Already saved it")
            elif d['index'] > idx:
                insertInto = idx
            else:
                insertInto = idx + 1
        elif len(self.sendDataLog) == 0:
            insertInto = 0
        t = data['type']
        kv = {'type':t, 'index':insertInto, 'address': data['address'], 'data':data['data']}
        self.sendDataLog.insert(insertInto, kv)
        self.printDataFlag = False
        log.success('insert succeed')


    def saveSendedLog(self, filename):
        with open(filename, 'wb') as f:
            for kv in self.sendDataLog:
                s = kv['type'] + ':'
                s += chr(len(kv['data']))
                if self.elf.arch == 'amd64':
                    s += p64(kv['address'])
                elif self.elf.arch == 'i386':
                    s += p32(kv['address'])
                s += kv['data']
                f.write(s)
        log.success("succeed")
        self.printDataFlag = False

    def run(self, mode):
        global io
        if mode == 'debug':
            timeout = 0.05
            io = process(self.binary)
        log.success("Running... (enter help to get help)")
        sendedData = ''
        recevedData = ''
        kv = 0
        idx = 0
        end = len(self.parsedLog)
        self.printDataFlag = True
        self.notEndFlag = True
        while True:
            if self.printDataFlag is True and self.notEndFlag is True:
                recevedData = self.recvDataTimeout(timeout)
            self.printDataFlag = True
            if self.inputFlag is True:
                inp = raw_input('>>> ').strip()
            if inp == '':
                if idx >= end:
                    log.warn("End")
                    self.inputFlag = True
                    self.notEndFlag = False
                    continue
                kv = self.printData(idx)
                data = kv['data']
                if kv['type'] == 'scanf':
                    sendedData = ''
                    data = raw_input('Data: ')
                try:
                    io.send(data)
                except:
                    log.failure("EOF")
                    self.inputFlag = True
                    continue
                sendedData += data
                idx += 1
                if self.currentAddress == 0:
                    self.currentAddress = kv['address']
                else:
                    if self.currentAddress != kv['address']:
                        self.currentAddress = kv['address']
                        inp = 's'
            elif inp == 'r':
                self.inputFlag = False
                self.printDataFlag = False
                recevedData = ''
                inp = ''
            elif inp == 'q':
                log.warn('quit')
                break

            elif inp == 'help':
                self.printDataFlag = False
                self.help()

            elif inp.startswith('sr'):
                self.printDataFlag = False
                inps = re.split(r'\W+', inp)
                if len(inps) == 1:
                    self.logRecvData(recevedData, 0, len(recevedData))
                    continue
                try:
                    s = int(inps[1], 16)
                    e = int(inps[2], 16)
                except:
                    log.warn("Unsupported args")
                    continue
                if len(inps) == 3:
                    self.logRecvData(recevedData, s, e)
                    continue
                if len(inps) != 4:
                    log.warn("Too much or less args")
                    continue
                try:
                    m = inps[3]
                except:
                    log.warn("Unsupported args")
                    continue
                self.logRecvData(recevedData, s, e, m)

            elif inp == 's':
                self.printDataFlag = False
                self.inputFlag = True
                if len(sendedData) == 0:
                    log.warn("Empty")
                    continue
                t = self.parsedLog[idx-1]['type']
                kv = {'type':t, 'index':idx-1, 'address': self.currentAddress, 'data':sendedData}
                self.sendDataLog.append(kv)
                log.success("Save sended data succeed: %s" %(kv['data']))
                sendedData = ''

            elif inp.startswith('x'):
                self.printDataFlag = False
                inps = re.split(r'\W+', inp)
                if len(inps) != 6:
                    log.warn("Too much or less args")
                    continue
                sr = inps[1]
                sridx = int(inps[2])
                s = int(inps[3], 16)
                e = int(inps[4], 16)
                m = inps[5]
                self.parseLogData(sr, sridx, s, e, m)

            elif inp.startswith('ls') or inp == 'ls':
                self.printDataFlag = False
                inps = re.split(r'\W+', inp)
                if inps[0] == 'lsa':
                    if len(inps) > 2:
                        log.warn("Too much or less args")
                        continue
                    elif len(inps) == 1:
                        self.list('a', 'info')
                        continue
                    elif len(inps) == 2:
                        self.list('a', inps[1])
                        continue
                if len(inps) == 1:
                    self.list('s')
                elif len(inps) == 2:
                    self.list('s', inps[1])
                elif len(inps) == 3:
                    self.list('s', inps[1], int(inps[2]))
                else:
                    log.warn("Too much or less args")

            elif inp.startswith('is'):
                inps = re.split(r'\W+', inp)
                if len(inps) != 2:
                    log.warn("Too much or less args")
                    continue
                try:
                    isidx = int(inps[1])
                except:
                    log.warn("Unsupported args")
                    continue
                self.insert(isidx, sendedData)

            elif inp.startswith('ms'):
                inps = re.split(r'\W+', inp)
                if len(inps) != 5:
                    log.warn("Too much or less args")
                    continue
                try:
                    si = int(inps[1])
                    s = int(inps[2], 16)
                    e = int(inps[3], 16)
                    ri = int(inps[4])
                except:
                    log.warn("Unsupported args")
                    continue
                self.modifySavedData(si, s, e, ri)

            elif inp.startswith('savelog'):
                inps = re.split(r'\W+', inp)
                if len(inps) != 2:
                    log.warn("Too much or less args")
                    continue
                try:
                    filename = inps[1]
                except:
                    log.warn("Unsupported args")
                    continue
                self.saveSendedLog(filename)

            elif inp == 'it':
                io.interactive()

            else:
                self.printDataFlag = False
                log.warn("Unknown command")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="AWD patch tool's log Applier")
    parser.add_argument("bin", help="/path/to/your/input binary")
    parser.add_argument("-l", "--log", help="/path/to/your/input pwnlog", required=True)
    parser.add_argument("--debug", action='store_true', help="add log mode")
    args = parser.parse_args()
    pwn = Pwnlog(args.log, args.bin)
    if args.debug:
        pwn.run('debug')
    else:
        pwn.run('debug')
