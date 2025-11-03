#core/capturer.py
import pcap
import threading
from PySide6.QtCore import QObject, Signal # (추가 v1.0) Qt 시그널 임포트

class PacketCapturer(QObject):
    """
    This class manages packet capturing in a separate thread.
    start() method to start capturing, stop() method to stop capturing.
    별도의 스레드에 패킷 캡처를 관리하느 클래스
    start() 메서드로 캡처 시작, stop() 메서드로 캡처 중지
    
    """
    #(추가 v1.0) "패킷 도착" 시그널 정의
    # 'object' 타입의 데이터(analysis 딕셔너리)를 전달할 것.
    packet_captured_signal = Signal(object)
    
    
    def __init__(self, analyzer):
        super().__init__() # (추가 v1.0) Qobject 부모 생성자 호출
        self._is_running = False
        self._capture_thread = None
        self._sniffer = None
        self._analyzer = analyzer
        # self.display_handler = display_handler -> CLI용
        
    def start(self, interface_name):
        """
        Start the capture thread
        캡처 스레드 시작
        
        """
        if self._is_running:
            print("이미 캡처가 진행 중입니다.")
            return
        
        print(f"\n>>'{interface_name}' 인터페이스에서 캡처를 시작합니다.")
        print(">>중지하려면 Enter 키를 누르세요.\n")
        
        # Generate pcap object
        # pcap 객체 생성
        try:
            self._sniffer = pcap.pcap(name=interface_name, promisc=True, immediate=True,timeout_ms=50)
        except Exception as e:
            print(f"[오류] pcap 객체를 생성할 수 없음.{e}")
            return
        
        self._is_running = True
        # Generate a thread to run _capture_loop method in the background
        # _capture_loop 메서드를 백그라운드에서 실행할 스레드 생성
        self._capture_thread = threading.Thread(target=self._capture_loop)
        self._capture_thread.start()
        
    def stop(self):
        """
        Stop the capture thread
        캡처 스레드 중지
        
        """
        if not self._is_running:
            return
        
        print("\n>> 캡처를 중지합니다...")
        self._is_running = False    # Set the flag to false to stop the loop
        if self._capture_thread:                            # 루프를 멈추도록 플래그를 false로 설정
            self._capture_thread.join() # Wait for the thread to fully terminate
                                        # 스레드가 완전히 종료될 때까지 대기
        print(">> 캡처가 중지되었습니다.")
        self._sniffer = None
    
    def _capture_loop(self):
        """ 
        Packet capture loop
        패킷 캡처 루프 
        
        """
        packet_cnt = 1
        # Unlimited loop while self._is_running is True
        # self._is_running이 True인 동안 무한루프
        
        while self._sniffer and self._is_running:
            try:
                # 
                # If no packet arrives within 100ms, None is returned and the loop continues.
                # 여러 패킷을 한번에 읽음 (readpkts)
                # 100ms 동안 패킷이 없으면 None 반환 루프는 계속됨.
                result = self._sniffer.readpkts() 
                if not result: continue

                # ---  디버깅 코드 추가  ---
                # 패킷이 잡혔는지 먼저 확인합니다.
                #print(f"DEBUG: Packet captured! Length: {len(result[1])}") 
                # ---  여기까지  ---
                
                for ts, packet_data in result:
                    #loop 내부에서도 중지 플래그 확인
                    if not self._is_running: break
                
                    #캡처한 데이터를 analyzer로 넘겨서 분석 요청
                    analysis = self._analyzer.analyze(ts,packet_data)
                
                    #분석 결과를 받아서 출력 (IP 정보가 존재하는 패킷만)
                    if analysis :
                        # (수정) display_handler 호출 대신 시그널 방출
                        analysis['id'] = packet_cnt # GUI에서 사용할 패킷 번호 추가
                        self.packet_captured_signal.emit(analysis)
                        # self.display_handler(packet_cnt,analysis) -> CLI용
                        packet_cnt += 1
                if not self._is_running: break
                
            
            except Exception as e:
                if not self._is_running: break        
                print(f"[캡쳐 오류] Loop error: {e}")
                