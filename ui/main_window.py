# ui/main_window.py
import sys
from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QComboBox,
    QPushButton, QTableWidget, QTableWidgetItem, QSplitter, QTextEdit, 
    QAbstractItemView, QHeaderView, QCheckBox, QMessageBox, QFileDialog
)
from PySide6.QtCore import Qt
from datetime import datetime
from utils.interface_finder import get_interfaces
from core.analyzer import PacketAnalyzer
from core.capturer import PacketCapturer
from ui.sensitive_info_window import SensitiveInfoWindow
from utils.csv_exporter import export_packets_to_csv
#----------------------------------------------------------------------------------
# 비암호화 트래픽을 간주할 포트 번호 집합
# (필요에 따라 포트 번호를 추가/제거)
UNENCRYPTED_PORTS = {
    80,     # HTTP
    8080,   # HTTP-alt
    20, 21, # FTP (Data, Control)
    69,     # TFTP
    23,     # Telnet
    53,     # DNS
}
#----------------------------------------------------------------------------------    
class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__() # QMainWindow 부모 생성자 호출
        self.setWindowTitle("Lightwire - Packet Analyzer prototype v1.2 (PySide6)")
        self.setGeometry(100, 100, 1000, 600)
        
        self.capturer = None
        self.analyzer = PacketAnalyzer()
        
        # 민감 정보 출력 윈도우 인스턴스 생성
        self.sensitive_window = SensitiveInfoWindow()
        
        self.all_packets = []
        # Main layout
        # 메인 레이아웃
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        main_layout = QVBoxLayout(main_widget)
        
        # 1. 상단 컨트롤 바
        control_widget = QWidget()
        control_layout = QHBoxLayout(control_widget)
        
        self.iface_combo = QComboBox()
        try:
            # get_interfaces가 문자열 리스트를 반환한다고 가정
            self.iface_combo.addItems([dev for dev in get_interfaces()])
        except Exception as e:
            print(f"인터페이스 로드 실패: {e}")
            self.iface_combo.addItem("인터페이스 로드 실패")
        
        # 패킷 캡처 시작 버튼
        self.start_button = QPushButton("캡처 시작")
        self.start_button.clicked.connect(self.start_capture)
         
        # 패킷 캡처 중지 버튼
        self.stop_button = QPushButton("캡처 중지")
        self.stop_button.clicked.connect(self.stop_capture)
        self.stop_button.setEnabled(False)
        
        # 로그 저장 버튼
        self.save_button = QPushButton("로그 저장")
        self.save_button.clicked.connect(self.save_packets_to_csv)
        self.save_button.setEnabled(False)
        
        
        # 비암호화 패킷 필터 ON/OFF 체크박스
        self.filter_checkbox = QCheckBox("비암호화 트래픽만 표시")
        self.filter_checkbox.setChecked(False) # 기본값: 필터 해제
        
        # 민감 정보를 담은 트래픽의 로그를 띄워주는 윈도우를 여는 버튼
        self.sensitive_button = QPushButton("민감 정보 로그 보기")
        self.sensitive_button.clicked.connect(self.sensitive_window.show)
        
        control_layout.addWidget(self.iface_combo) # 네트워크 인터페이스 콤보박스
        control_layout.addWidget(self.start_button) # 캡처 시작 버튼
        control_layout.addWidget(self.stop_button)  # 캡처 중단 버튼
        control_layout.addWidget(self.save_button)  # 로그 저장 버튼
        control_layout.addWidget(self.filter_checkbox) # 필터 적용/해제 체크박스
        control_layout.addWidget(self.sensitive_button) # 민감 정보 로그 버튼
        control_layout.addStretch() # 버튼들 왼쪽 정렬
        main_layout.addWidget(control_widget)
        
        # 2. 스플리터 (상단 테이블/ 하단 페이로드 뷰)
        splitter = QSplitter(Qt.Vertical)
        main_layout.addWidget(splitter)
        
        # 3. 패킷 테이블 (상단)
        self.packet_table = QTableWidget()
        self.packet_table.setColumnCount(7)
        self.packet_table.setHorizontalHeaderLabels(["No.","Time", "Source IP", "Src Port", "Destination IP", "Dst Port", "Protocol"])
        self.packet_table.verticalHeader().setVisible(False)
        
        self.packet_table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.packet_table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.packet_table.itemSelectionChanged.connect(self.display_payLoad)
        self.packet_table.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeToContents)
        self.packet_table.horizontalHeader().setSectionResizeMode(2,QHeaderView.Stretch)
        self.packet_table.horizontalHeader().setSectionResizeMode(4,QHeaderView.Stretch)
        splitter.addWidget(self.packet_table)
        
        # 4. 페이로드 텍스트 뷰 (하단)
        self.payload_view = QTextEdit()
        self.payload_view.setReadOnly(True)
        self.payload_view.setFontFamily("Consolas")
        splitter.addWidget(self.payload_view)
        
        splitter.setSizes([400, 200])  # 초기 크기 비율 설정
        
        self.packet_store = {}  # 페이로드 저장을 위한 딕셔너리
        
        
    def start_capture(self):
        selected_iface = self.iface_combo.currentText()
        
        # 예외처리 : 유효하지 않은 인터페이스 선택 시
        if not selected_iface or "실패" in selected_iface or "없음" in selected_iface:
            return
        
        # --- [수정] 텍스트 파싱 로직 ---
        # 콤보박스에 있는 "이더넷[\Device\NPF_...]"에서
        # 대괄호 안의 "\Device\NPF_... 부분만 추출"
        interface_name = selected_iface
        if "[" in selected_iface and selected_iface.endswith("]"):
            # '[' 기준으로 나누고, 맨 뒤쪽 덩어리에서 마지막글자 (']')를 뺌.
            interface_name = selected_iface.split("[")[-1][:-1]
        # ------------------------------
        
        # --- 디버깅용 출력 ---
         # print(f"DEBUG : 캡처 요청 ID -> {interface_name}")
        # ---------------------
        
        self.sensitive_window.clear_log() # 패킷 캡처 시작 시 민감정보 로그 창 초기화
        self.capturer = PacketCapturer(self.analyzer)
        # 시그널과 슬롯 연결
        self.capturer.packet_captured_signal.connect(self.add_packet_to_table)

        self.capturer.start(interface_name)
        
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)
        self.iface_combo.setEnabled(False)
        self.save_button.setEnabled(False) # 캡처 중에는 저장 비활성화
        self.filter_checkbox.setEnabled(False)
        self.packet_table.setRowCount(0)
        self.packet_store.clear()
        self.all_packets.clear()
            
    def stop_capture(self):
        if self.capturer:
            self.capturer.stop()
            self.capturer = None
            
        self.start_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.iface_combo.setEnabled(True)
        if self.all_packets:
            self.save_button.setEnabled(True) # 캡처가 멈추면 저장 버튼 활성화
        self.filter_checkbox.setEnabled(True) # 캡처가 멈추면 필터 체크박스 활성화
   
   
    # 슬롯 함수 : 비암호화 패킷 필터링 로직
    def add_packet_to_table(self, analysis):
        """
        백그라운드 스레드로부터 analysis 딕셔너리를 받아 테이블에 추가
        """
        self.all_packets.append(analysis)
        # 필터가 켜져 있을 때
        if self.filter_checkbox.isChecked() :
            src_port = analysis.get('src_port')
            dst_port = analysis.get('dst_port')
            # Ip 패킷이 아니거나, 출발지/도착지 포트가 모두 비암호화 포트 목록에 없을 때 필터링
            if not analysis.get('src_ip') or \
                (src_port not in UNENCRYPTED_PORTS and
                 dst_port not in UNENCRYPTED_PORTS) :
                 return
        
        if not analysis.get('src_ip'):
            return
        
        # 민감 정보가 존재하면 새 윈도우(민감정보 윈도우)로 전달    
        if analysis.get('sensitive_info'):
            self.sensitive_window.add_sensitive_packet(analysis)
            
        # 테이블에 패킷 정보 행 추가
        row_cnt = self.packet_table.rowCount()
        self.packet_table.insertRow(row_cnt)
            
        protocol_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
        protocol_name = protocol_map.get(analysis['protocol'], str(analysis.get('protocol', 'N/A')))
        cap_time = datetime.fromtimestamp(analysis['timestamp']).strftime("%H:%M:%S.%f")
            
        # 페이로드 데이터를 별도 저장 (딕셔너리)
        packet_id = row_cnt + 1
        analysis['display_id'] = packet_id
        self.packet_store[packet_id] = analysis.get('payload_str','No Payload Data')
        
        if analysis.get('sensitive_info'):
            self.sensitive_window.add_sensitive_packet(analysis)
            
            
        self.packet_table.setItem(row_cnt, 0, QTableWidgetItem(str(packet_id)))
        self.packet_table.setItem(row_cnt, 1, QTableWidgetItem(cap_time))
        self.packet_table.setItem(row_cnt, 2, QTableWidgetItem(analysis['src_ip']))
        self.packet_table.setItem(row_cnt, 3, QTableWidgetItem(str(analysis.get('src_port', 'N/A'))))
        self.packet_table.setItem(row_cnt, 4, QTableWidgetItem(analysis['dst_ip']))
        self.packet_table.setItem(row_cnt, 5, QTableWidgetItem(str(analysis.get('dst_port', 'N/A'))))
        self.packet_table.setItem(row_cnt, 6, QTableWidgetItem(protocol_name))
            
        self.packet_table.scrollToBottom()
       
    def display_payLoad(self):
        # 테이블 행 클릭 시 하단 뷰에 페이로드를 표시
        selcted_items = self.packet_table.selectedItems()
        if not selcted_items:
            return
            
        packet_id_item = self.packet_table.item(selcted_items[0].row(), 0)
        if packet_id_item:
            packet_id = int (packet_id_item.text())
            self.payload_view.setText(self.packet_store.get(packet_id, ''))
            
            
    def closeEvent(self, event):
        # 메인 창을 닫을 때 스레드 종료
        self.stop_capture()
        self.sensitive_window.close() # 민감 정보 윈도우도 닫기
        event.accept()

    def save_packets_to_csv(self):
        """저장 버튼을 눌렀을 때 실행되는 슬롯 함수"""
        
        # 1. 방어 코드 (Validation)
        # 저장할 데이터가 없을 때 함수 종료
        if not self.all_packets:
            QMessageBox.warning(self, "저장 불가","저장할 패킷 데이터가 없습니다.")
            return
        
        # 2. 파일 저장 대화상자 열기 (UI)
        file_path, _ = QFileDialog.getSaveFileName(
            self,"로그 파일 저장", "", "CSV Files (*.csv);;All Files (*)"
        )
        
        if not file_path:
            return # 사용자가 저장을 취소한 경우 함수 종료
        
        try:
            # 3. 별도 모듈에게 저장 명령(로직 위임)
            export_packets_to_csv(self.all_packets, file_path)
            
            # 4. 결과 알림 (UI)
            QMessageBox.information(self, "저장 완료", f"성공적으로 저장되었습니다.\n{file_path}")
            
        except Exception as e:
            QMessageBox.critical(self, "저장 실패", f"파일 저장 중 오류가 발생했습니다.\n{str(e)}")