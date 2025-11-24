from PySide6.QtWidgets import QWidget, QVBoxLayout, QTextEdit,QPushButton
from PySide6.QtGui import QFont

class SensitiveInfoWindow(QWidget):
    """
    민감 정보가 포함된 패킷만 따로 모아서 출력하는 창
    """
    
    def __init__(self):
        super().__init__()
        self.setWindowTitle("민감 정보 감지 로그")
        self.setGeometry(200,200,600,400)
        
        layout = QVBoxLayout(self)
        
        # 상단 Clear 버튼 : 로그를 지우는 기능
        self.clear_button = QPushButton("로그 지우기")
        self.clear_button.clicked.connect(self.clear_log)
        layout.addWidget(self.clear_button)
        
        # 로그 텍스트 영역
        self.log_display = QTextEdit()
        self.log_display.setReadOnly(True)
        self.log_display.setFontFamily("Consolas")
        layout.addWidget(self.log_display)
        
    def add_sensitive_packet(self, analysis):
        """ 
        MainWindow로부터 민감 정보가 포함된 패킷을 받아 텍스트 창에 출력
        """
        
        try:
            protocol_map = {6:'TCP',17:'UDP',1:'ICMP'}
            protocol = protocol_map.get(analysis['protocol'], str(analysis.get('protocol','N/A')))
            packet_no = analysis.get('display_id', analysis['id'])
            log_entry = (
                f"===============================================================\n"
                f"[!] 민감 키워드 '{analysis.get('sensitive_keyword','N/A')}' 감지!\n"
                f"Packet #{packet_no} ({protocol})\n"
                f"From: {analysis['src_ip']}:{analysis.get('src_port', 'N/A')}\n"
                f"To:   {analysis['dst_ip']}:{analysis.get('dst_port', 'N/A')}\n"
                f"----------------- Payload -----------------\n"
                f"{analysis.get('payload_str', 'No Payload Data')}\n"
                f"===============================================================\n\n"
            )
            
            self.log_display.append(log_entry)
            self.log_display.verticalScrollBar().setValue(
                self.log_display.verticalScrollBar().maximum()
            )
        except Exception as e:
            self.log_display.append(f"[!] 로그 추가 중 오류 발생: {e}\n")
            
    def clear_log(self):
        self.log_display.clear()
        
    def closeEvent(self, event):
        """ 
        창 닫기 버튼을 누르면 창이 숨겨짐(삭제되지 않음)
        (MainWidow가 닫힐 때 같이 닫힘)
        """
        
        event.ignore()
        self.hide()