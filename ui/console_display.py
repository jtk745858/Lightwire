# ui/console_display.py

from datetime import datetime

# 분석된 딕셔너리 대신 timestamp와 packet_data를 직접 받도록 변경
def display_packet_info(packet_count, analysis):
    """
    분석이 완료된 패킷 딕셔너리를 받아 콘솔에 출력.
    """
    if not analysis or not analysis.get('src_ip'):
        return
    
    cap_time = datetime.fromtimestamp(analysis['timestamp']).strftime('%H:%M:%S.%f')
    
    # protocol 번호를 이름으로 변환
    protocol_map = {6: 'TCP', 17: 'UDP',1: 'ICMP'}
    protocol_name = protocol_map.get(analysis['protocol'], str(analysis['protocol']))
    
    print(
        f"[{packet_count:04d}] {cap_time} | "
        f"{protocol_name:<5} | "
        f"{analysis['src_ip']}:{analysis['src_port']} -> "
        f"{analysis['dst_ip']}:{analysis['dst_port']}"
    )