import socket
import struct
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
        #파싱 결과를 담을 변수 초기화
        analysis_result = {
            'timestamp' : timestamp, 
            'src_mac' : None, 'dst_mac' : None, 'eth_type' : None,   #L2
            'src_ip' : None,'dst_ip' : None,                         #L3
            'protocol' : None, 'src_port' : None, 'dst_port' : None  #L4
         }
        try:
            """
                1. L2) Ethernet 프레임 파싱 (고정 14byte)
            """
            if len(packet_data) < 14:
                return None #패킷이 너무 작음

            # 이더넷 헤더 파싱
            eth_header = struct.unpack('!6s6sH',packet_data[0:14])
            # 6s : 6byte를 바이트 문자열로 읽음 (목적지 mac주소)
            # 6s : 6byte를 바이트 문자열로 읽음 (출발지 mac주소)
            # H : 2byte를 unsined 정수로 읽음 (EtherType)
            analysis_result['dst_mac'] = eth_header[0].hex(':')
            analysis_result['src_mac'] = eth_header[1].hex(':')
            eth_type = eth_header[2]
            analysis_result['eth_type'] = eth_type
            
            #ip 헤더의 시작 부분을 인덱스 14로 설정
            ip_header_start = 14
            
            if eth_type == 0x8100: #이더넷 헤더가 VLAN으로 인해 18바이트일 경우
                if len(packet_data) < 18:
                    return None #패킷이 너무 작음
                
                real_eth_type = struct.unpack('!H',packet_data[16:18])[0]
                eth_type = real_eth_type
                ip_header_start = 18 # ip 헤더의 시작 부분을 인덱스 18로 설정
                    
            """
                2. L3) IP 헤더 파싱 (가변 길이 처리)
            """
            if eth_type == 0x0800: # IPv4 일 경우 L3 파싱 시작
                #L3 헤더 시작점부터 최소 20byte의 헤더가 존재하는지 확인.
                if len(packet_data) < ip_header_start + 20 :
                    return analysis_result #L2 정보만 리턴
                
                first_byte = packet_data[ip_header_start]
                ihl = first_byte & 0x0F # ihl은 IP헤더가 4byte 묶음이 몇개인지 보여주는 값. 
               
                ip_header_length = ihl * 4 #L4의 시작점을 찾기 위함.
                
                #IP 헤더 부분의 20byte만 추출
                #(IP헤더는 가변길이로 20byte보다 크더라도 나머지 데이터들은 파싱할 의미가 거의 없음.)
                #(Lightwire는 핵심 데이터만 파싱하는것이 목적)
                ip_header_data = packet_data[ip_header_start : ip_header_start + 20]
                
                #ip헤더의 20바이트만큼 파싱
                ip_parts = struct.unpack('!9xB2x4s4s',ip_header_data)
                # 9x : 9byte 건너뜀(Version, IHL, Total Lenght, ID, Flags, Fragment Offset등의 데이터를 담고있음)
                # B : 1byte를 unsigned char로 읽음(protocol number : 6=TCP, 17=UDP,1=ICMP)
                # 2x : 2byte 건너뜀(Header Checksum 데이터)
                # 4s : 4byte를 바이트 문자열로 읽음 (출발지 Ip 주소)
                # 4s : 4byte를 바이트 문자열로 읽음 (목적지 Ip 주소) 
                protocol = ip_parts[0]
                analysis_result['protocol'] = protocol
                analysis_result['src_ip'] = socket.inet_ntoa(ip_parts[1]) # 출발지 ip주소 저장, 10진수 문자열 IP주소로 변환하는 inet_ntoa()함수
                analysis_result['dst_ip'] = socket.inet_ntoa(ip_parts[2]) # 목적지 ip주소 저장, 10진수 문자열 IP주소로 변환하는 inet_ntoa()함수
                """
                    3. L4) 전송계층 헤더 파싱       
                """    
                # 전송계층 헤더의 시작 지점 = IP 헤더의 시작지점 + IP 헤더의 길이
                # L4 데이터 슬라이싱
                transport_layer_start = ip_header_start + ip_header_length
                transport_layer_data = packet_data[transport_layer_start:]
            
                # protocol의 값이 6일 때 TCP 파싱 / 17일 때 UDP 파싱 / 그 외의 값은 파싱을 하지 않음
                # TCP protocol 파싱 (20byte ~ 60byte의 가변길이)
                if protocol == 6 : # TCP
                    if len(transport_layer_data) < 20 :
                        return analysis_result
                
                    ports = struct.unpack('!HH',transport_layer_data[0:4])
                    # H : 2byte를 unsigned 정수로 읽음 (출발지 포트)
                    # H : 2byte를 unsigned 정수로 읽음 (도착지 포트)
                    analysis_result['src_port'] = ports[0] # 출발지 포트 데이터 저장
                    analysis_result['dst_port'] = ports[1] # 도착지 포트 데이터 저장
            
                    
                # UDP protocol 파싱 (8byte 고정길이)
                elif protocol == 17 : # UDP 
                    if len(transport_layer_data) < 8 :
                        return analysis_result
                
                    ports = struct.unpack('!HH',transport_layer_data[0:4]) # 포트에 대한 데이터만 파싱.
                    # H : 2byte를 unsigned 정수로 읽음 (출발지 포트)
                    # H : 2byte를 unsigned 정수로 읽음 (도착지 포트)
                    analysis_result['src_port'] = ports[0] # 출발지 포트 데이터 저장
                    analysis_result['dst_port'] = ports[1] # 도착지 포트 데이터 저장
            
            return analysis_result
            
        except Exception as e:
            print(f"[오류] 파싱할 수 없는 패킷.{e}")
            return None
        
        