#utils/interface_finder.py
import pcap

def get_interfaces():
    """
    사용 가능한 모든 네트워크 인터페이스를 찾아 리스트로 반환
    오류 발생 시 빈 리스트 반환
    """
    try:
        interfaces = pcap.findalldevs()
        return interfaces
    except Exception as e:
        #Npcap이 설치되지 않았거나 권한 문제가 있을 때 오류 발생 가능
        print(f"Error finding interfaces: {e}")
        print("Please ensure Npcap is installed and you have the necessary permissions.")
        
        return []