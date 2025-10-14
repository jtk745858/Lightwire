#core/capturer.py

import pcap
from datetime import datetime

def start_capture(interface_name, packets_count=20):
    """
    지정한 네트워크 인터페이스에서 패킷을 캡처
    
    Args:
        interface_name (str): 캡처할 네트워크 인터페이스 이름
        packets_count (int): 캡처할 최대 패킷수    

    """
    print(f"\n>> '{interface_name}' 인터페이스에서 패킷 캡처 시작... (총 {packets_count})\n")
    
    try:
        # pcap 객체 생성
        # promisc =True :  네트워크의 모든 패킷을 수신
        # immediate=True : 패킷을 버퍼링 없이 즉시 처리
        
        sniffer = pcap.pcap(name=interface_name, promisc=True, immediate=True)
        # 캡처된 패킷 순회
        for i, (timestamp, packet_data) in enumerate(sniffer, 1) :
            # 타임스탬프를 읽을 수 있도록 변환
            cap_time = datetime.fromtimestamp(timestamp).strftime('%Y-%m-%d %H:%M:%S.%f')
            
            # 캡처된 패킷 정보 출력
            print(f"[{i:02d}] Time: {cap_time} | Length: {len(packet_data)} Bytes")

            # 지정된 패킷 수에 도달하면 캡처 중지
            if i >= packets_count : 
                break
            
    except Exception as e:
        print(f"[오류] 캡처 중 문제가 발생했습니다: {e}")