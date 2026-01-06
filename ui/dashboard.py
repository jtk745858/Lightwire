#Lightwire/ui/dashboard.py
from PySide6.QtWidgets import QWidget, QHBoxLayout, QLabel, QFrame
from PySide6.QtCore import Qt
from PySide6.QtGui import QFont

class DashboardWidget(QWidget):
    
    def __init__(self):
        super().__init__()
        
        # 카운트 변수 초기화
        self.total_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.sensitive_count = 0
        
        self.init_ui()
        
    def init_ui(self):
        layout = QHBoxLayout()
        layout.setContentsMargins(15, 10, 15, 10)
        self.setLayout(layout)
        
        self.setObjectName("DashboardFrame")
        
        # 스타일: 회색 박스 배경에 둥근 모서리
        self.setStyleSheet("""
             #DashboardFrame {
                background-color: #f5f5f5;
                border-radius: 10px;
                border: 1px solid #e0e0e0;
                }
                QLabel {
                    border: none;
                    padding: 0px;
                }
            }
        """)
        
        #라벨 생성 도우미 함수
        def create_stat_label(title, color):
            lbl = QLabel(f"{title}: 0")
            # 폰트 설정 : 굵게, 크기 11
            lbl.setFont(QFont("Segoe UI", 11, QFont.Bold))
            lbl.setStyleSheet(f"color: {color}; background-color: transparent;")
            
            return lbl
        
        # 1. 항목별 라벨 생성
        self.lbl_total = create_stat_label("Total", "#333333") # 검정
        self.lbl_tcp = create_stat_label("TCP", "#1976D2")     # 파랑
        self.lbl_udp = create_stat_label("UDP", "#F57C00")     # 주황
        self.lbl_sensitive = create_stat_label("Sensitive", "#D32F2F") # 빨강

        # 2. 구분선 생성 함수
        def create_separator():
            line = QFrame()
            line.setFrameShape(QFrame.VLine)
            line.setFrameShadow(QFrame.Sunken)
            line.setStyleSheet("background-color: #cccccc; border: none;")
            line.setFixedWidth(1)
            return line

        # 3. 레이아웃 배치
        layout.addWidget(self.lbl_total)
        layout.addSpacing(20)
        layout.addWidget(create_separator())
        layout.addSpacing(20)
        
        layout.addWidget(self.lbl_tcp)
        layout.addSpacing(15)
        layout.addWidget(self.lbl_udp)
        
        layout.addSpacing(20)
        layout.addWidget(create_separator())
        layout.addSpacing(20)
        
        layout.addWidget(self.lbl_sensitive)
        
        layout.addStretch(1) # 오른쪽 여백 추가
        
        
    def update_stats(self, analysis):
        """
        패킷이 들어올 때마다 호출되어 숫자를 갱신.
        """
        self.total_count += 1
        
        proto = analysis.get('protocol')
       
        if proto == 6:
            self.tcp_count += 1
        elif proto == 17:
            self.udp_count += 1
        elif proto == 1:
            self.icmp_count += 1
        
        if analysis.get('sensitive_info'):
            self.sensitive_count += 1
        
        # 화면 갱신
        self.lbl_total.setText(f"Total: {self.total_count}")
        self.lbl_tcp.setText(f"TCP: {self.tcp_count}")
        self.lbl_udp.setText(f"UDP: {self.udp_count}")
        self.lbl_sensitive.setText(f"Sensitive: {self.sensitive_count}")
        
    
    def reset_stats(self):
        """
        새 캡쳐 시작 시 0으로 초기화
        """
        self.total_count = 0
        self.tcp_count = 0
        self.udp_count = 0
        self.icmp_count = 0
        self.sensitive_count = 0
        
        # 화면 갱신
        self.lbl_total.setText("Total: 0")
        self.lbl_tcp.setText("TCP: 0")
        self.lbl_udp.setText("UDP: 0")
        self.lbl_sensitive.setText("Sensitive: 0")           
           

