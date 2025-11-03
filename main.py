# main.py
import sys
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow # (수정 v1.0) console_display -> main_window import

def main():
    """
    Lightwire GUI App
    """
    
    # Qt Application 생성
    app = QApplication(sys.argv)
    
    # 메인 윈도우 생성 및 표시
    window = MainWindow()
    window.show()
    
    # 이벤트 루프 시작
    sys.exit(app.exec())
    
if __name__ == "__main__":
    main()
