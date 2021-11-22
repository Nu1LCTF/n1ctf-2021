import concurrent.futures
import subprocess

flag = bytearray(b"n1ctf{" + b"}" * 110)
payloads = []


class StateMachine:
    fin_cnt = 0
    offset = None

    def dispatch(self, to_victim, is_fin, payload):
        if not is_fin and to_victim and len(payload) > 1600:
            # attack payload
            self.payload = payload
        if is_fin:
            self.fin_cnt += 1
            if self.fin_cnt == 2 and not to_victim:  # last fin from victim
                assert (self.payload != None)
                payloads.append(self.payload)


p = subprocess.getoutput(
    "tshark -r /mnt/r/cap.pcapng -T fields -E separator=, -e tcp.dstport -e tcp.flags.fin -e tcp.payload -e tcp.stream "
    "-E header=n tcp.port==9999")
streams = dict()
for i in p.splitlines():
    if i.find(',') == -1:
        continue
    dstport, is_fin, payload, streamid = i.split(',')
    is_fin = (is_fin == "1")
    payload = bytes.fromhex(payload)
    streamid = int(streamid)
    s = streams.setdefault(streamid, StateMachine())
    s.dispatch(dstport == "9999", is_fin, payload)


def proc(x):
    sp = subprocess.Popen("python ../t.py", shell=True, stdin=subprocess.PIPE, stdout=subprocess.PIPE)
    sp.stdin.write((x.hex() + "\n").encode('ascii'))
    res = sp.stdout.readline().strip()
    sp.wait()
    print(res)
    flag[int(res.split(b' ')[1])] = ord(res.split(b' ')[0])


pl = concurrent.futures.ThreadPoolExecutor(16)
print(len(payloads))

for i in payloads:
    pl.submit(proc, i)
pl.shutdown(True)
print(bytes(flag))
