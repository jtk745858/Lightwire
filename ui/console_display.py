# ui/console_display.py

from datetime import datetime


#----------------------------------------------------------------------------------
# (추가 v0.3) 비암호화 트래픽을 간주할 포트 번호 집합
# (필요에 따라 포트 번호를 추가/제거)
UNENCRYPTED_PORTS = {
    80,     # HTTP
    20, 21, # FTP
    23,     # Telnet
    25,     # SMTP
    53,     # DNS
    110,    # POP3
    143,    # IMAP
}
#----------------------------------------------------------------------------------    
    
# 분석된 딕셔너리 대신 timestamp와 packet_data를 직접 받도록 변경
def display_packet_info(packet_count, analysis, state):
    """
    분석이 완료된 패킷 딕셔너리를 받아 콘솔에 출력.
    """
    
    #------------------------------------------------------------------------------
    # (추가v0.3) 필터링 로직
    # 1. 필터가 켜져있고 (state.filter_enabled == True)
    # 2. IP 패킷이 아니거나
    # 3. 출발지/목적지 포트 둘 다 비암호화 포트 목록에 속하지않으면
    #    -> 아무것도 출력하지 않고 함수를 종료
    
    if (state.filter_endabled and 
       (not analysis.get('src_ip') or 
       (analysis.get('src_port') not in UNENCRYPTED_PORTS and
        analysis.get('dst_port')  not in UNENCRYPTED_PORTS))):
        return
    
    #------------------------------------------------------------------------------
    if not analysis or not analysis.get('src_ip'):
        return
    
    cap_time = datetime.fromtimestamp(analysis['timestamp']).strftime('%H:%M:%S.%f')
    
    # Exchange protocol number to name
    # protocol 번호를 이름으로 변환
    protocol_map = {6: 'TCP', 17: 'UDP',1: 'ICMP'}
    protocol_name = protocol_map.get(analysis['protocol'], str(analysis['protocol']))
    
    print(
        f"[{packet_count:04d}] {cap_time} | "
        f"{protocol_name:<5} | "
        f"{analysis['src_ip']}:{analysis['src_port']} -> "
        f"{analysis['dst_ip']}:{analysis['dst_port']}"
    )