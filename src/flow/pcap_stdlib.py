"""Minimal read-only PCAP/IPv4 parser used when Scapy is unavailable.
It intentionally parses headers and metadata only; it never injects packets.
"""
from __future__ import annotations
import struct, socket
from typing import Iterator, Dict, Any

class PcapFormatError(ValueError): pass

def _ip_checksum_valid(header):
    if len(header)!=20: return False
    if len(header)%2: header+=b"\0"
    total=sum(struct.unpack("!10H",header))
    return ((total>>16)+(total&0xffff)) & 0xffff == 0xffff

def _parse_dns(payload):
    if len(payload)<12: return None
    flags=struct.unpack("!H",payload[2:4])[0]
    qdcount=struct.unpack("!H",payload[4:6])[0]
    if qdcount<1: return None
    pos=12; labels=[]
    try:
        for _ in range(64):
            ln=payload[pos]; pos+=1
            if ln==0: break
            if ln>63 or pos+ln>len(payload): return None
            labels.append(payload[pos:pos+ln].decode("ascii","replace")); pos+=ln
        if pos+4>len(payload): return None
        qtype,qclass=struct.unpack("!HH",payload[pos:pos+4])
        return {"query":".".join(labels),"response_code":flags & 0xf,"nxdomain":(flags & 0xf)==3,"qtype":qtype}
    except (IndexError,struct.error):
        return None

def iter_packets(path:str)->Iterator[Dict[str,Any]]:
    with open(path,"rb") as fh:
        gh=fh.read(24)
        if len(gh)!=24: raise PcapFormatError("PCAP global header is truncated")
        magic=gh[:4]
        if magic==b"\xd4\xc3\xb2\xa1":
            endian="<"; ts_scale=1_000_000
        elif magic==b"\xa1\xb2\xc3\xd4":
            endian=">"; ts_scale=1_000_000
        elif magic==b"\x4d\x3c\xb2\xa1":
            endian="<"; ts_scale=1_000_000_000
        elif magic==b"\xa1\xb2\x3c\x4d":
            endian=">"; ts_scale=1_000_000_000
        else: raise PcapFormatError("unsupported PCAP magic")
        _,major,minor,zone,sigfigs,snaplen,network=struct.unpack(endian+"IHHIIII",gh)
        if network!=1: raise PcapFormatError(f"unsupported link type {network}; Ethernet(1) required")
        while True:
            ph=fh.read(16)
            if not ph: break
            if len(ph)!=16: raise PcapFormatError("truncated packet header")
            sec,frac,inc_len,orig_len=struct.unpack(endian+"IIII",ph)
            if inc_len>snaplen or inc_len>64*1024*1024: raise PcapFormatError("invalid packet length")
            raw=fh.read(inc_len)
            if len(raw)!=inc_len: raise PcapFormatError("truncated packet data")
            if len(raw)<14: continue
            ethertype=struct.unpack("!H",raw[12:14])[0]
            if ethertype!=0x0800: continue
            ip=raw[14:]
            if len(ip)<20: continue
            ihl=(ip[0]&0xf)*4
            if ihl<20 or len(ip)<ihl: continue
            total_len=struct.unpack("!H",ip[2:4])[0]
            proto=ip[9]
            src=socket.inet_ntoa(ip[12:16]); dst=socket.inet_ntoa(ip[16:20])
            transport=ip[ihl: min(len(ip), total_len if total_len>=ihl else len(ip))]
            sport=dport=0; flags=0; app_payload=b""; dns=None
            if proto==6 and len(transport)>=20:
                sport,dport,seq,ack,off_flags,window,checksum,urg=struct.unpack("!HHIIHHHH",transport[:20])
                flags=off_flags & 0x1ff; off=((off_flags>>12)&0xf)*4
                app_payload=transport[off:] if len(transport)>=off else b""
            elif proto==17 and len(transport)>=8:
                sport,dport,ulen,checksum=struct.unpack("!HHHH",transport[:8]); app_payload=transport[8:]
            elif proto==1:
                if len(transport)>=8: sport=dport=0
            if proto==17 and (sport==53 or dport==53):
                dns=_parse_dns(app_payload)
            yield {"timestamp":sec+frac/ts_scale,"length":len(raw),"src":src,"dst":dst,
                   "protocol":proto,"sport":sport,"dport":dport,"flags":flags,
                   "payload":app_payload,"dns":dns}
