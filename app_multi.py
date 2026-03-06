from flask import Flask, render_template, request, jsonify, send_file
from scapy.all import rdpcap, Raw
import tempfile
import os
import zipfile
import io
import time
from werkzeug.utils import secure_filename
import os.path

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 500 * 1024 * 1024  # 500MB 제한

def get_template_name():
    """사용 가능한 템플릿 파일을 반환 (multi_upload.html 우선, 없으면 index.html)"""
    templates_dir = os.path.join(app.root_path, 'templates')
    
    # multi_upload.html이 있으면 사용
    multi_upload_path = os.path.join(templates_dir, 'multi_upload.html')
    if os.path.exists(multi_upload_path):
        print("📄 Using multi_upload.html (multi-file upload version)")
        return 'multi_upload.html'
    
    # 없으면 index.html 사용
    index_path = os.path.join(templates_dir, 'index.html')
    if os.path.exists(index_path):
        print("📄 Using index.html (single-file upload version)")
        return 'index.html'
    
    # 둘 다 없으면 에러
    print("❌ No template files found!")
    return None

def format_hex_dump(data, bytes_per_row=16):
    """Create formatted hex dump with offset, hex, and ASCII columns"""
    rows = []
    for i in range(0, len(data), bytes_per_row):
        chunk = data[i:i + bytes_per_row]
        offset = f"{i:08x}"
        hex_bytes = ' '.join(f"{b:02x}" for b in chunk)
        hex_bytes = hex_bytes.ljust(bytes_per_row * 3 - 1)
        ascii_repr = ''.join(chr(b) if 32 <= b <= 126 else '.' for b in chunk)
        rows.append({
            'offset': offset,
            'hex': hex_bytes,
            'ascii': ascii_repr
        })
    return rows

def analyze_single_pcap(file_path, filename):
    """단일 PCAP 파일 분석"""
    try:
        packets = rdpcap(file_path)
        rules = []
        payload_info = []
        seen_payloads = set()
        false_positive_score = 0
        rule_id = 1000001
        
        print(f"Analyzing {filename}: {len(packets)} packets")
        
        for i, packet in enumerate(packets):
            if Raw in packet:
                payload = bytes(packet[Raw].load)
                
                if len(payload) == 0:
                    continue
                
                # 패턴 탐지
                important_patterns = []
                if b'${jndi:' in payload:
                    important_patterns.append("🚨 LOG4J SHELL ATTACK DETECTED!")
                if b'/WEB-INF/' in payload or b'WEB-INF' in payload:
                    important_patterns.append("⚠️ WEB-INF PATH DISCLOSURE")
                if b'GET /' in payload or b'POST /' in payload:
                    important_patterns.append("🌐 HTTP Request")
                
                # Payload 정보 생성
                payload_str = payload.decode('utf-8', errors='ignore')
                full_hex = ' '.join(f"{b:02x}" for b in payload)
                hex_rows = format_hex_dump(payload)
                
                printable_chars = sum(1 for b in payload if 32 <= b <= 126)
                printable_percent = round((printable_chars / len(payload)) * 100, 1) if payload else 0
                
                payload_info.append({
                    'packet_num': i + 1,
                    'length': len(payload),
                    'full_hex': full_hex[:1000] + ('...' if len(full_hex) > 1000 else ''),
                    'hex_rows': hex_rows[:10],  # 처음 10행만
                    'full_ascii': ''.join(chr(b) if 32 <= b <= 126 else '.' for b in payload)[:500],
                    'payload': payload_str[:500] + ('...' if len(payload_str) > 500 else ''),
                    'patterns': important_patterns,
                    'has_pattern': len(important_patterns) > 0,
                    'printable_percent': printable_percent
                })
                
                # Snort 룰 생성
                if payload_str not in seen_payloads:
                    content = payload_str[:30].replace('"', '\\"').replace('\n', ' ').replace('\r', ' ').strip()
                    
                    if len(content) < 4:
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
        
        if rules:
            false_positive_score = min(100, false_positive_score / len(rules))
        else:
            false_positive_score = 0
        
        return {
            'filename': filename,
            'success': True,
            'packet_count': len(packets),
            'payload_count': len(payload_info),
            'rules': rules[:50],  # 처음 50개 룰만
            'rule_count': len(rules),
            'payload_info': payload_info[:30],  # 처음 30개 페이로드만
            'false_positive_score': round(false_positive_score, 2),
            'has_patterns': any(p['has_pattern'] for p in payload_info)
        }
        
    except Exception as e:
        return {
            'filename': filename,
            'success': False,
            'error': str(e)
        }

@app.route('/', methods=['GET'])
def index():
    """메인 페이지 - 사용 가능한 템플릿 자동 선택"""
    template_name = get_template_name()
    
    if template_name is None:
        return "Error: No template files found. Please add multi_upload.html or index.html to templates folder.", 500
    
    return render_template(template_name)

@app.route('/analyze', methods=['POST'])
def analyze_files():
    if 'pcap_files' not in request.files:
        return jsonify({'error': 'No files uploaded'}), 400
    
    files = request.files.getlist('pcap_files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No files selected'}), 400
    
    results = []
    total_start_time = time.time()
    
    for file in files:
        if file and (file.filename.endswith('.pcap') or file.filename.endswith('.pcapng')):
            filename = secure_filename(file.filename)
            
            # 임시 파일 저장
            temp_fd, temp_path = tempfile.mkstemp(suffix='.pcap')
            try:
                file.save(temp_path)
                result = analyze_single_pcap(temp_path, filename)
                results.append(result)
            finally:
                os.close(temp_fd)
                if os.path.exists(temp_path):
                    os.remove(temp_path)
    
    total_time = round(time.time() - total_start_time, 2)
    
    # 통계 계산
    total_files = len(results)
    successful = sum(1 for r in results if r['success'])
    failed = total_files - successful
    total_rules = sum(r.get('rule_count', 0) for r in results if r['success'])
    total_packets = sum(r.get('packet_count', 0) for r in results if r['success'])
    
    return jsonify({
        'results': results,
        'statistics': {
            'total_files': total_files,
            'successful': successful,
            'failed': failed,
            'total_rules': total_rules,
            'total_packets': total_packets,
            'processing_time': total_time
        }
    })

@app.route('/download/rules', methods=['POST'])
def download_rules():
    """모든 룰을 하나의 파일로 다운로드"""
    data = request.get_json()
    results = data.get('results', [])
    
    # 룰 파일 생성
    rule_content = "# Snort Rules Generated by PCAP Analyzer\n"
    rule_content += f"# Generated: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
    rule_content += "#" + "="*50 + "\n\n"
    
    for result in results:
        if result.get('success') and result.get('rules'):
            rule_content += f"# File: {result['filename']}\n"
            rule_content += f"# Packets: {result['packet_count']}, Rules: {result['rule_count']}\n"
            rule_content += "#" + "-"*40 + "\n"
            for rule in result['rules']:
                rule_content += rule + "\n"
            rule_content += "\n"
    
    # 파일 전송
    mem_file = io.BytesIO()
    mem_file.write(rule_content.encode('utf-8'))
    mem_file.seek(0)
    
    return send_file(
        mem_file,
        mimetype='text/plain',
        as_attachment=True,
        download_name=f'snort_rules_{time.strftime("%Y%m%d_%H%M%S")}.rules'
    )

@app.route('/download/zip', methods=['POST'])
def download_zip():
    """개별 결과를 ZIP 파일로 다운로드"""
    data = request.get_json()
    results = data.get('results', [])
    
    mem_zip = io.BytesIO()
    
    with zipfile.ZipFile(mem_zip, 'w', zipfile.ZIP_DEFLATED) as zf:
        for result in results:
            if result.get('success'):
                filename = result['filename'].replace('.pcap', '').replace('.pcapng', '')
                
                # 룰 파일
                rule_content = f"# Snort Rules for {result['filename']}\n"
                rule_content += f"# False Positive Score: {result['false_positive_score']}/100\n"
                rule_content += "#" + "="*50 + "\n\n"
                for rule in result.get('rules', []):
                    rule_content += rule + "\n"
                
                zf.writestr(f'{filename}_rules.txt', rule_content)
                
                # 요약 파일
                summary = f"""PCAP Analysis Report
========================
File: {result['filename']}
Total Packets: {result['packet_count']}
Packets with Payload: {result['payload_count']}
Rules Generated: {result['rule_count']}
False Positive Score: {result['false_positive_score']}/100
Has Attack Patterns: {result['has_patterns']}

Patterns Detected:
"""
                for p in result.get('payload_info', []):
                    if p.get('patterns'):
                        summary += f"\nPacket {p['packet_num']}: {', '.join(p['patterns'])}"
                
                zf.writestr(f'{filename}_summary.txt', summary)
    
    mem_zip.seek(0)
    return send_file(
        mem_zip,
        mimetype='application/zip',
        as_attachment=True,
        download_name=f'pcap_analysis_{time.strftime("%Y%m%d_%H%M%S")}.zip'
    )

if __name__ == '__main__':
    print("="*50)
    print("PCAP Analyzer - Multi-file Upload Version")
    print("="*50)
    
    # 템플릿 파일 확인
    template_name = get_template_name()
    if template_name:
        print(f"✅ Using template: {template_name}")
    else:
        print("❌ Warning: No template files found in templates directory!")
        print("   Please add multi_upload.html or index.html")
    
    print("Starting server on http://127.0.0.1:5000")
    print("Max file size: 500MB")
    print("Support multiple PCAP/PCAPNG files")
    print("="*50)
    app.run(debug=True, host='127.0.0.1', port=5000)