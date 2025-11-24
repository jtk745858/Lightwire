# utils/interface_finder.py
import pcap
import subprocess
import re
import codecs

def get_interfaces():
    """
    Returns a list of all network interfaces that can be captured by pcap
    pcap으로 캡처 가능한 모든 네트워크 인터페이스 목록을 반환합니다.
    
    """
    try:
        return pcap.findalldevs()
    except Exception as e:
        print(f"[오류] 네트워크 인터페이스를 찾는 데 실패했습니다: {e}")
        return []