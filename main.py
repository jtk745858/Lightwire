# main.py
from utils.interface_finder import get_interfaces
from core.analyzer import PacketAnalyzer # Import the PacketAnalyer
from core.capturer import PacketCapturer # Import the PacketCapturer class
from ui.console_display import display_packet_info
def main():
    """
    Lightwire Network Packet Analyzer Main Function
    This function initializes the packet analyzer and starts capturing packets.
    It uses the pcap library for packet capturing and dpkt for packet parsing.

    Lightwire 네트워크 패킷 분석기 메인함수.
    이 함수는 패킷 분석과 패킷 캡처를 시작하는 함수임.
    이 프로그램은 pcap 라이브러리를 사용하여 패킷을 캡처 및 파싱함.
   
    """
    print("=================================")
    print("Lightwire - Packet Analyzer v0.2 ")
    print("=================================")

    # Bringing up the network interfaces
    # 사용 가능한 네트워크 인터페이스 가져오기
    interfaces = get_interfaces()
    
    # If there are no interfaces, exit the program
    # 인터페이스가 없으면 프로그램 종료
    if not interfaces:
        input("\nEnter 키를 눌러 종료...")
        return  
    
    # Display the list of interfaces to the user
    # 사용자에게 인터페이스 목록을 보여줌
    print("\n[사용 가능한 네트워크 인터페이스 목록]")
    for i, dev_name in enumerate(interfaces):
        print(f"  [{i}] {dev_name}")

    # Select an interface to capture packets from user
    # 사용자로부터 캡처할 인터페이스를 선택받음
    try:
        choice = int(input("\n>> 캡처할 인터페이스의 번호를 입력하세요: "))
        selected_interface_name = interfaces[choice]
    except (ValueError, IndexError):
        print("\n[오류] 잘못된 번호를 입력했습니다. 프로그램을 종료합니다."); return
    
    if selected_interface_name:
        # 1. Generate and connect analyzer and capturer
        # 1. 분석기와 캡처기 객체 생성 및 연결
        analyzer = PacketAnalyzer()
        capturer = PacketCapturer(analyzer=analyzer, display_handler=display_packet_info)
        # 2. start capturing packets (in a separate thread
        # 2. 패킷 캡처 시작 (별도의 스레드에서 실행)
        capturer.start(selected_interface_name)
        
        # 3. Wait for user to press Enter
        # 3. 사용자가 Enter 키를 입력할 때까지 대기
        input()
        
        # 4. Stop capturing packets
        # 4. 패킷 캡처 중지
        capturer.stop()
        
if __name__ == "__main__":
    main()