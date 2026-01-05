# utils/interface_finder.py
import pcap
import csv
import io
import sys
import subprocess


def get_interfaces():
    """
    Returns a list of all network interfaces that can be captured by pcap
    pcap으로 캡처 가능한 모든 네트워크 인터페이스 목록을 반환.
    
    Windows의 'getmac' 명령어 사용.
    친숙한 인터페이스 이름과 장치 경로를 매핑하여 반환함.
    
    """
    interfaces = []
    
    try:
        cmd = ["getmac", "/v", "/fo", "csv"]
        
        result = subprocess.run(cmd,capture_output=True, text=True,encoding='cp949')
        
        if result.returncode != 0:
            return ["Error: 권한 부족 또는 명령 실패"]
        
        # 2. CSV 파싱
        f = io.StringIO(result.stdout)
        reader = csv.DictReader(f)
        
        for row in reader:
            # getmac 출력 컬럼명: "연결 이름", "네트워크 어댑터", "실제 주소", "전송 이름"
            # (영문 윈도우일 경우: "Connection Name", "Network Adapter", "Physical Address")
            
            # 키값 호환성을 위해 컬럼명을 확인하거나 인덱스로 접근하지 않고 DictReader 사용
            # 한글 윈도우 기준 키값
            friendly_name = row.get("연결 이름") or row.get("Connection Name")
            transport_name = row.get("전송 이름") or row.get("Transport Name")
            
            # 3. 유효 장치만 필터링
            # "미디어 연결 끊김" 상태인 장치는 전송 이름이 비어있을 수 있음.
            if not friendly_name or not transport_name:
                continue
            
            # Loopback, Bluetooth, Virtual 등 불필요 어댑터 제외
            if "Bluetooth" in friendly_name or "Loopback" in friendly_name:
                continue
            
            # 4. pcap 호환 경로로 변환
            
            pcap_name = transport_name.replace("Tcpip","NPF")
            
            # 5. UI에 보여줄 문자열 구성
            display_str = f"{friendly_name} [{pcap_name}]"
            interfaces.append(display_str)
            
    except Exception as e:
        return [f"Error: {str(e)}"]
    
    if not interfaces:
        return ["활성화된 인터페이스 없음"]
    
    
    return interfaces
 
    