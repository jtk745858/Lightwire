# Lightwire/utils/csv_exporter.py
import csv
from datetime import datetime
def export_packets_to_csv(packets, file_path):
    """
    패킷 리스트를 받아 지정된 경로에 CSV 파일로 저장하는 함수.
    :param packets: 저장할 패킷 데이터 리스트 (List[dict])
    :param file_path: 저장할 파일 경로 (str)
    :return: 성공 시 True, 실패 시 Exception 발생.
    """
    
    try:
        # utf-8-sig: 엑셀에서 한글 깨짐 방지.
        with open(file_path, mode='w', newline='',encoding='utf-8-sig') as f:
            writer = csv.writer(f)
            
            # 1. 헤더 작성
            writer.writerow([
                "Time", "Src IP", "Src Port", "Dst IP", "Dst Port","Protocol",
                "Sensitive Info", "Keword", "Payload Preview"
                ])
            
            # 2. 패킷 데이터 작성
            proto_map = {6: 'TCP', 17: 'UDP', 1: 'ICMP'}
            
            for pkt in packets: 
                # 타임스탬프 변환
                ts = datetime.fromtimestamp(pkt['timestamp']).strftime('%Y-%m-%d %H:%M:%S.%f')
                proto = proto_map.get(pkt['protocol'], str(pkt.get('protocol', '')))
                
                # 민감 정보 여부 확인
                is_sensitive = "O" if pkt.get('sensitive_info') else ""
                keyword = pkt.get('sensitive_info', '')
                
                # 페이로드는 너무 길면 100자만 잘라서 저장(줄바꿈 제거)
                payload = pkt.get('payload', '').replace('\n',' ')[:100]
                
                writer.writerow([
                    ts,
                    pkt.get('src_ip', ''),
                    pkt.get('src_port', ''),
                    pkt.get('dst_ip', ''),
                    pkt.get('dst_port', ''),
                    proto,
                    is_sensitive,
                    keyword,
                    payload
                ])
        return True
                
    except Exception as e:
        raise e