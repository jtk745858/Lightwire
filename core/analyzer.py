import socket
import struct
import re
#----------------------------------------------------------------------------------
# 민감정보 키워드 목록 정의
# (필요에 따라 키워드 추가/제거)
# (payload_data는 bytes이므로 키워드도 bytes로 정의)
SENSITIVE_KEYWORDS = [
    b'password', b'pass', b'passwd',b'pwd',
    b'username', b'userid', b'uid', b'login',
    b'ssn', b'creditcard', b'cardnum', b'user:',b'id=',b'passwd=',
    b'user=',b'password=',b'pwd=',b'userid=',b'username=',b'uid='
]
#----------------------------------------------------------------------------------
class PacketAnalyzer:
    """
    This class parse and analyze captured raw packet data.
    It return the result as a dictionary.
    캡쳐된 원시 패킷 데이터를 직접 파싱하여 분석.
    결과를 딕셔너리 형태로 반환
    
    """
    def __init__(self):
        pass
    
    def analyze(self, timestamp,packet_data):
        # Reset analysis result
        # 파싱 결과를 담을 변수 초기화
        analysis_result = {
            'timestamp' : timestamp, 
            'src_mac' : None, 'dst_mac' : None, 'eth_type' : None,   #L2
            'src_ip' : None,'dst_ip' : None,'protocol' : None,       #L3 
            'src_port' : None, 'dst_port' : None,                    #L4
            'payload_str' : ''    # (추가 v1.0) L7 페이로드 문자열  
         }
        try:
            """
                1. L2) Ethernet Frame parsing (Fixed 14byte / VLAN is 18byte handling)
                1. L2) Ethernet 프레임 파싱 (고정 14byte / VLAN 18byte 처리)
            """
            if len(packet_data) < 14:
                return None     # packet is too small
                                # 패킷이 너무 작음
            # Parse Ethernet header
            # 이더넷 헤더 파싱
            eth_header = struct.unpack('!6s6sH',packet_data[0:14])
            # 6s : 6byte를 바이트 문자열로 읽음 (목적지 mac주소)
            #      Read 6bytes as byte string (Destination mac address)
            # 6s : 6byte를 바이트 문자열로 읽음 (출발지 mac주소)
            #      Read 6bytes as byte string (Source mac address)
            # H : 2byte를 unsined 정수로 읽음 (EtherType)
            #     Read 2bytes as unsigned integer (EtherType)
            
            analysis_result['dst_mac'] = eth_header[0].hex(':')
            analysis_result['src_mac'] = eth_header[1].hex(':')
            eth_type = eth_header[2]
            analysis_result['eth_type'] = eth_type
            
            # Set IP header start index to 14 
            # ip 헤더의 시작 부분을 인덱스 14로 설정
            ip_header_start = 14
            
            if eth_type == 0x8100:  # If Ethernet header is 18 bytes due to VLAN
                                    # 이더넷 헤더가 VLAN으로 인해 18바이트일 경우
                if len(packet_data) < 18:
                    return None # Packet is too small 
                                # 패킷이 너무 작음
                
                real_eth_type = struct.unpack('!H',packet_data[16:18])[0]
                eth_type = real_eth_type
                ip_header_start = 18    # Set IP header start index to 18 (if VLAN)
                                        # ip 헤더의 시작 부분을 인덱스 18로 설정 (VLAN인 경우)
                    
            """
                2. L3) IP header parsing (Variable length handling)
                2. L3) IP 헤더 파싱 (가변 길이 처리)
            """
            if eth_type == 0x0800:  # If Ipv4, start IP header parsing
                                    # IPv4 일 경우 L3 파싱 시작
                                    
                # Check if there are at least 20 bytes of header from L3 header start
                # L3 헤더 시작점부터 최소 20byte의 헤더가 존재하는지 확인.
                if len(packet_data) < ip_header_start + 20 :
                    return analysis_result  # Return only L2 info
                                            # L2 정보만 리턴
                
                first_byte = packet_data[ip_header_start]
                ihl = first_byte & 0x0F # ihl is the lower 4 bits of the first byte
                                        # ihl은 IP헤더가 4byte 묶음이 몇개인지 보여주는 값. 
               
                ip_header_length = ihl * 4  # Look for L4 start point
                                            # L4의 시작점을 찾기 위함.
                
                # Extract only the IP header part 20 bytes
                # IP 헤더 부분의 20byte만 추출
                # (IP header is variable length and if longer than 20bytes, other data no have much meaning to parse.)
                # (Lightwire aims to parse only core data)
                # (IP헤더는 가변길이로 20byte보다 크더라도 나머지 데이터들은 파싱할 의미가 거의 없음.)
                # (Lightwire는 핵심 데이터만 파싱하는것이 목적)
                ip_header_data = packet_data[ip_header_start : ip_header_start + 20]
                
                # Parse 20bytes of IP header
                # ip헤더의 20바이트만큼 파싱
                ip_parts = struct.unpack('!9xB2x4s4s',ip_header_data)
                # 9x : 9byte 건너뜀(Version, IHL, Total Lenght, ID, Flags, Fragment Offset등의 데이터를 담고있음)
                #      Jump 9bytes (Contains data such as version, IHL, total lengthm ID, Flags, Fragment offset etc.)
                # B : 1byte를 unsigned char로 읽음(protocol number : 6=TCP, 17=UDP,1=ICMP)
                #     Read 1byte as unsigned char (protocol number : 6=TCP, 17=UDP,1=ICMP)
                # 2x : 2byte 건너뜀(Header Checksum 데이터)
                #      Jump 2bytes (Header checksum data)
                # 4s : 4byte를 바이트 문자열로 읽음 (출발지 Ip 주소)
                #      Read 4bytes as byte string (Source Ip address)
                # 4s : 4byte를 바이트 문자열로 읽음 (목적지 Ip 주소) 
                #      Read 4bytes as byte string (Destination Ip address)
                protocol = ip_parts[0]
                analysis_result['protocol'] = protocol
                analysis_result['src_ip'] = socket.inet_ntoa(ip_parts[1]) # 출발지 ip주소 저장, 10진수 문자열 IP주소로 변환하는 inet_ntoa()함수
                analysis_result['dst_ip'] = socket.inet_ntoa(ip_parts[2]) # 목적지 ip주소 저장, 10진수 문자열 IP주소로 변환하는 inet_ntoa()함수
                
                """
                    3. L4) Translate layer header parsing
                    3. L4) 전송계층 헤더 파싱       
                """    
                # Start point of transport layer header = start point of IP header + length of IP header
                # 전송계층 헤더의 시작 지점 = IP 헤더의 시작지점 + IP 헤더의 길이
                # Slice transport layer data
                # L4 데이터 슬라이싱
                transport_layer_start = ip_header_start + ip_header_length
                transport_layer_data = packet_data[transport_layer_start:]

                payload_start = 0
                payload_data =b''
                # If protocol = 6(TCP) or 17(UDP), parse port information, otherwise do not parse.
                # protocol의 값이 6일 때 TCP 파싱 / 17일 때 UDP 파싱 / 그 외의 값은 파싱을 하지 않음
                
                # Parse TCP protocol(20byte ~ 60byte variable length)
                # TCP protocol 파싱 (20byte ~ 60byte의 가변길이)
                if protocol == 6 : # TCP
                    if len(transport_layer_data) < 20 :
                        return analysis_result
                
                    ports = struct.unpack('!HH',transport_layer_data[0:4])
                    # H : 2byte를 unsigned 정수로 읽음 (출발지 포트)
                    # H : 2byte를 unsigned 정수로 읽음 (도착지 포트)
                    analysis_result['src_port'] = ports[0] # 출발지 포트 데이터 저장
                    analysis_result['dst_port'] = ports[1] # 도착지 포트 데이터 저장
                    
                    # (추가 v1.0) L7 시작점 계산 (TCP)
                    tcp_header_byte_12 = transport_layer_data[12]
                    data_offset = (tcp_header_byte_12 & 0xF0) >> 4  # 상위 4비트가 데이터 오프셋
                    tcp_header_length = data_offset * 4
                    payload_start = transport_layer_start + tcp_header_length
                    payload_data = packet_data[payload_start:]
                    
                # Parse UDP protocol (8byte fixed length)
                # UDP protocol 파싱 (8byte 고정길이)
                elif protocol == 17 : # UDP 
                    if len(transport_layer_data) < 8 :
                        return analysis_result
                
                    ports = struct.unpack('!HH',transport_layer_data[0:4]) # 포트에 대한 데이터만 파싱.
                    # H : 2byte를 unsigned 정수로 읽음 (출발지 포트)
                    # H : 2byte를 unsigned 정수로 읽음 (도착지 포트)
                    analysis_result['src_port'] = ports[0] # 출발지 포트 데이터 저장
                    analysis_result['dst_port'] = ports[1] # 도착지 포트 데이터 저장

                    # (추가 v1.0) L7 시작점 계산 (UDP)
                    payload_start = transport_layer_start + 8
                    
                    payload_data = packet_data[payload_start:]
                    
                """ 
                4. (added v1.0) L7) Payload analysis
                4. (추가 v1.0) L7) 페이로드 분석
                """
                if payload_start > 0 and payload_start < len(packet_data):
                    payload_data = packet_data[payload_start:]
                    try:
                        # Try to decode payload as Unencrypted text (UTF-8)
                        # 비암호화 프로토콜은 디코딩 시도
                        analysis_result['payload_str'] = payload_data.decode('utf-8')
                    except UnicodeDecodeError:
                        # 바이너리 데이터는 16진수 문자열로 표현
                        analysis_result['payload_str'] = payload_data.hex(' ')
                    # 민감 정보 탐지로직
                    # 페이로드를 소문자로 변환하여 키워드를 발견하면 플레그를 세우고 저장
                    payload_lower = payload_data.lower()
                    for keyword in SENSITIVE_KEYWORDS:
                        if keyword in payload_lower:
                            analysis_result['sensitive_info'] = True
                            analysis_result['sesitive_keyword'] = keyword.decode('utf-8')
                            break
                
            return analysis_result
            
        except Exception as e:
            print(f"[오류] 파싱할 수 없는 패킷.{e}")
            return None
        
        