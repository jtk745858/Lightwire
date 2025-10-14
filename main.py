# main.py
from core.capturer import start_capture
from utils.interface_finder import get_interfaces
import pcap
import dpkt

def main():
    """
    Lightweight Network Packet Analyzer Main Function
    This function initializes the packet analyzer and starts capturing packets.
    It uses the pcap library for packet capturing and dpkt for packet parsing.

    """
    print("===================================")
    print("Lightweight - Packet-Analyzer v0.1 ")
    print("===================================")

    # 사용 가능한 네트워크 인터페이스 가져오기
    interface = get_interfaces()
    
    # 인터페이스가 없으면 프로그램 종료
    if not interface:
        input("Press Enter to exit...")
        return  
    
    # 사용자에게 인터페이스 목록을 보여줌
    print("\nAvailable Network Interfaces:")
    for i,dev_name in enumerate(interface) :
        print(f" [{i}] {dev_name}")
    # 사용자로부터 캡처할 인터페이스를 선택받음
    try:
        choice = int(input("\n>> 캡처할 인터페이스 번호 입력: "))
        selected_interface_name = interface[choice]
    except (ValueError, IndexError):
        print("\n[오류] 잘못된 번호를 입력했습니다. 프로그램을 종료합니다.")
        return
    
    if selected_interface_name:
        start_capture(selected_interface_name)
        
        
if __name__ == "__main__":
    main()