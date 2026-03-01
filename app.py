from flask import Flask, render_template, request
from scapy.all import rdpcap, Raw, IP, TCP, UDP
import tempfile
import os
import binascii

app = Flask(__name__)

def format_hex_dump(data, bytes_per_row=16):
    """Create formatted hex dump with offset, hex, and ASCII columns"""
    rows = []
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i:i + bytes_per_row]
        
        # Offset
        offset = f"{i:08x}"
        
        # Hex bytes
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        hex_bytes = hex_bytes.ljust(bytes_per_row * 3 - 1)  # Pad for alignment
        
        # ASCII representation
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        
        rows.append({
            'offset': offset,
            'hex': hex_bytes,
            'ascii': ascii_repr
        })
    return rows

def analyze_packets(packets):
    """패킷 분석 - 모든 Payload 표시"""
    rules = []
    payload_info = []
    seen_payloads = set()
    false_positive_score = 0
    rule_id = 1000001
    
    print(f"Total packets: {len(packets)}")
    
    for i, packet in enumerate(packets):
        if Raw in packet:
            payload = bytes(packet[Raw].load)
            
            # 빈 페이로드 제외
            if len(payload) == 0:
                continue
            
            # 중요 패턴 탐지
            important_patterns = []
            
            # Log4j 공격 패턴
            if b'${jndi:' in payload:
                important_patterns.append("🚨 LOG4J SHELL ATTACK DETECTED!")
            
            # Tomcat AJP / WEB-INF 노출
            if b'/WEB-INF/' in payload or b'WEB-INF' in payload:
                important_patterns.append("⚠️ WEB-INF PATH DISCLOSURE")
            
            # HTTP 요청
            if b'GET /' in payload or b'POST /' in payload:
                important_patterns.append("🌐 HTTP Request")
            
            # Payload 정보 생성
            payload_str = payload.decode('utf-8', errors='ignore')
            
            # 전체 Hex 덤프 생성
            full_hex = ' '.join(f"{b:02x}" for b in payload)
            
            # Hex 테이블 행 생성
            hex_rows = format_hex_dump(payload)
            
            # Payload 통계
            printable_chars = sum(1 for b in payload if 32 <= b <= 126)
            printable_percent = round((printable_chars / len(payload)) * 100, 1) if payload else 0
            null_count = sum(1 for b in payload if b == 0)
            
            # ASCII 범위
            if all(32 <= b <= 126 for b in payload):
                ascii_range = "All printable"
            elif any(32 <= b <= 126 for b in payload):
                ascii_range = "Mixed"
            else:
                ascii_range = "Binary"
            
            payload_info.append({
                'index': i,
                'packet_num': i + 1,
                'length': len(payload),
                'full_hex': full_hex,
                'hex_rows': hex_rows,
                'full_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload),
                'payload': payload_str[:500] + ('...' if len(payload_str) > 500 else ''),
                'patterns': important_patterns,
                'has_pattern': len(important_patterns) > 0,
                'printable_percent': printable_percent,
                'null_count': null_count,
                'ascii_range': ascii_range
            })
            
            # Snort 룰 생성 (중복 제외)
            if payload_str not in seen_payloads:
                # content 필드 이스케이프
                content = payload_str[:30].replace('"', '\\"').replace('\n', ' ').replace('\r', ' ').strip()
                
                if len(content) < 4:
                    # 바이너리 데이터는 헥스값으로 룰 생성
                    hex_content = '|' + ''.join(f"{b:02x}" for b in payload[:8]) + '|'
                    rule = f'alert ip any any -> any any (msg:"Binary Payload Rule"; content:"{hex_content}"; sid:{rule_id};)'
                else:
                    rule = f'alert ip any any -> any any (msg:"Payload Rule"; content:"{content}"; sid:{rule_id};)'
                
                rules.append(rule)
                seen_payloads.add(payload_str)
                
                # FP 점수 계산
                length_factor = min(30, len(payload) / 10)
                binary_ratio = 1 - (printable_chars / max(len(payload), 1))
                binary_factor = binary_ratio * 40
                
                pattern_factor = 0
                if important_patterns:
                    if "LOG4J" in str(important_patterns):
                        pattern_factor = -20
                    elif "WEB-INF" in str(important_patterns):
                        pattern_factor = -10
                
                false_positive_score += max(0, length_factor + binary_factor + pattern_factor)
                rule_id += 1
    
    # FP 점수 정규화
    if rules:
        false_positive_score = min(100, false_positive_score / len(rules))
    else:
        false_positive_score = 0
    
    return rules, round(false_positive_score, 2), payload_info

def process_pcap_file(file_storage):
    """PCAP 파일 처리"""
    temp_fd, temp_path = tempfile.mkstemp(suffix='.pcap')
    
    try:
        # 파일 저장
        file_storage.save(temp_path)
        file_size = os.path.getsize(temp_path)
        print(f"File saved: {temp_path} ({file_size} bytes)")
        
        if file_size == 0:
            return [], 0, [{"error": "Empty file"}]
        
        # PCAP 읽기
        try:
            packets = rdpcap(temp_path)
            print(f"Successfully read {len(packets)} packets")
        except Exception as e:
            print(f"Error reading pcap: {e}")
            import traceback
            traceback.print_exc()
            return [], 0, [{"error": f"Pcap read error: {str(e)}"}]
        
        # 패킷 분석
        rules, fp_score, payload_info = analyze_packets(packets)
        
        return rules, fp_score, payload_info
        
    except Exception as e:
        print(f"Error processing file: {e}")
        import traceback
        traceback.print_exc()
        return [], 0, [{"error": f"Error: {str(e)}"}]
        
    finally:
        os.close(temp_fd)
        if os.path.exists(temp_path):
            os.remove(temp_path)

@app.route('/', methods=['GET', 'POST'])
def index():
    rules = []
    false_positive_score = 0
    payload_info = []
    error_message = None
    stats = {}

    if request.method == 'POST':
        if 'pcap_file' not in request.files:
            error_message = 'No file uploaded'
        else:
            file = request.files['pcap_file']
            
            if file.filename == '':
                error_message = 'No file selected'
            else:
                print(f"\n=== Processing file: {file.filename} ===")
                rules, false_positive_score, payload_info = process_pcap_file(file)
                
                if not rules and not payload_info:
                    error_message = 'No packets with payload found in the file'
                else:
                    stats = {
                        'total_packets': len(payload_info),
                        'packets_with_patterns': len([p for p in payload_info if p.get('has_pattern', False)]),
                        'rules_generated': len(rules),
                        'total_bytes': sum(p.get('length', 0) for p in payload_info)
                    }

    return render_template('index.html', 
                         rules=rules, 
                         false_positive_score=false_positive_score, 
                         payload_info=payload_info,
                         error=error_message,
                         stats=stats)

# ⭐⭐⭐ 중요: 이 부분이 반드시 있어야 합니다! ⭐⭐⭐
if __name__ == '__main__':
    print("Starting PCAP Analyzer on http://127.0.0.1:5000")
    app.run(debug=True, host='127.0.0.1', port=5000)