# main.py
import keyboard # (추가 v0.3) 키보드 라이브러리
from utils.interface_finder import get_interfaces
from core.analyzer import PacketAnalyzer # Import the PacketAnalyer
from core.capturer import PacketCapturer # Import the PacketCapturer class
from ui.console_display import display_packet_info

#-----------------------------------------------------------------------------------
# (추가 v0.3) 필터 상태를 저장하고 공유하기 위한 클래스
class CaptureState:
    def __init__(self):
        # True이면 필터 적용, False이면 필터 미적용
        self.filter_endabled = False
        
    def set_filter(self, endabled) : 
        if self.filter_endabled == endabled :
            return
        
        self.filter_endabled = endabled
        if endabled :
            print("\n┌───────────────────────────────────────────┐")
            print("\n>> [필터 적용됨] 비암호화 트래픽만 표시합니다 <<")
            print("\n└───────────────────────────────────────────┘")
        else :
            print("\n┌───────────────────────────────────────────┐")
            print("\n>> [필터 해제됨] 모든 캡처트래픽을 표시합니다 <<")
            print("\n└───────────────────────────────────────────┘")

#-----------------------------------------------------------------------------------



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
    print("Lightwire - Packet Analyzer v0.3 ")
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
        
        # 1. (추가 v0.3) 필터링 상태 객체 생성
        state = CaptureState()
        
        # 2. Generate and connect analyzer and capturer
        # 2. 분석기 객체 생성 및 연결
        analyzer = PacketAnalyzer()
        
        # 3. (추가 v0.3) display_hadler가 state 객체를 함께 받도록 lanbda 함수로 래핑.
        display_wrapper = lambda packet_count, analysis: (
            display_packet_info(packet_count, analysis, state)
        )
        
        # 4. (수정 v0.3) 래핑된 display_handler를 capturer에 전달
        capturer = PacketCapturer(analyzer=analyzer, display_handler=display_wrapper)
        
        # 5. (추가 v0.3) 키보드 핫키 설정
        try:
            keyboard.add_hotkey('1', lambda: state.set_filter(True))
            keyboard.add_hotkey('2', lambda: state.set_filter(False))
            print("\n >> 캡처 실행 중 '1' 키 -> 비암호화 트래픽만 표시 \n   '2' 키 -> 모든 트래픽 표시")
            
        except ImportError:
            print("\n[경고] 'keyboard' 라이브러리 오류. hotkey 기능 사용 불가")
            print("         관리자 권한으로 프로그램을 실행하거나 'keyboard' 라이브러리를 설치하세요.\n")
        
        # 6. start capturing packets (in a separate thread
        # 6. 패킷 캡처 시작 (별도의 스레드에서 실행)
        capturer.start(selected_interface_name)
        
        # 7. Wait for user to press Enter
        # 7. 사용자가 Enter 키를 입력할 때까지 대기
        input()
        
        # 8. Stop capturing packets
        # 8. 패킷 캡처 중지
        capturer.stop()
        
if __name__ == "__main__":
    main()