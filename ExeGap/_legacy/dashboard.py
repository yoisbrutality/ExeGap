#!/usr/bin/env python3
"""
Web Dashboard for EXE Decompiler Analysis Results
Flask-based visualization interface
"""
import flask
import json
import os
from flask import Flask, render_template_string, request, send_file, jsonify
from pathlib import Path
import hashlib

app = Flask(__name__)
ANALYSIS_RESULTS = {}


DASHBOARD_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>EXE Decompiler Dashboard</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1400px;
            margin: 0 auto;
        }
        
        header {
            background: rgba(255, 255, 255, 0.95);
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        }
        
        h1 {
            color: #667eea;
            margin-bottom: 10px;
            font-size: 2.5em;
        }
        
        .subtitle {
            color: #666;
            font-size: 0.95em;
        }
        
        .dashboard {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(350px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            transition: transform 0.3s ease, box-shadow 0.3s ease;
        }
        
        .card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0, 0, 0, 0.2);
        }
        
        .card h3 {
            color: #667eea;
            margin-bottom: 15px;
            font-size: 1.3em;
            border-bottom: 2px solid #667eea;
            padding-bottom: 10px;
        }
        
        .stat {
            display: flex;
            justify-content: space-between;
            padding: 10px 0;
            border-bottom: 1px solid #f0f0f0;
        }
        
        .stat label {
            font-weight: 600;
            color: #333;
        }
        
        .stat value {
            color: #667eea;
            font-family: 'Courier New', monospace;
        }
        
        .security-alert {
            background: #fff3cd;
            border-left: 4px solid #ffc107;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        
        .security-alert.danger {
            background: #f8d7da;
            border-left-color: #dc3545;
        }
        
        .security-alert.success {
            background: #d4edda;
            border-left-color: #28a745;
        }
        
        .import-list {
            max-height: 300px;
            overflow-y: auto;
            background: #f9f9f9;
            padding: 10px;
            border-radius: 5px;
        }
        
        .import-item {
            padding: 8px;
            margin: 5px 0;
            background: white;
            border-left: 3px solid #667eea;
            font-family: 'Courier New', monospace;
            font-size: 0.9em;
        }
        
        .import-item.suspicious {
            border-left-color: #dc3545;
            color: #dc3545;
        }
        
        .import-item.category-process {
            border-left-color: #ff6b6b;
        }
        
        .import-item.category-injection {
            border-left-color: #ee5a6f;
        }
        
        .import-item.category-memory {
            border-left-color: #f06595;
        }
        
        .grid-2 {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .full-width {
            grid-column: 1 / -1;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 15px;
        }
        
        th {
            background: #f5f5f5;
            padding: 12px;
            text-align: left;
            font-weight: 600;
            color: #333;
            border-bottom: 2px solid #ddd;
        }
        
        td {
            padding: 12px;
            border-bottom: 1px solid #eee;
        }
        
        tr:hover {
            background: #f9f9f9;
        }
        
        .hash-value {
            font-family: 'Courier New', monospace;
            font-size: 0.85em;
            word-break: break-all;
            color: #666;
        }
        
        .tag {
            display: inline-block;
            background: #667eea;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 0.85em;
            margin: 3px;
        }
        
        .tag.danger {
            background: #dc3545;
        }
        
        .tag.warning {
            background: #ffc107;
            color: #333;
        }
        
        .tag.success {
            background: #28a745;
        }
        
        .progress-bar {
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            overflow: hidden;
            margin: 10px 0;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #667eea, #764ba2);
            transition: width 0.3s ease;
        }
        
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            .grid-2 {
                grid-template-columns: 1fr;
            }
            h1 {
                font-size: 1.8em;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 EXE Decompiler Dashboard</h1>
            <p class="subtitle">Advanced Binary Analysis & Extraction Suite</p>
        </header>
        
        <div class="dashboard" id="dashboard">
            <div class="card">
                <h3>📊 Binary Information</h3>
                <div class="stat">
                    <label>Filename:</label>
                    <value id="filename">-</value>
                </div>
                <div class="stat">
                    <label>File Size:</label>
                    <value id="filesize">-</value>
                </div>
                <div class="stat">
                    <label>MD5 Hash:</label>
                </div>
                <value class="hash-value" id="md5">-</value>
                <div class="stat" style="margin-top: 10px;">
                    <label>SHA256:</label>
                </div>
                <value class="hash-value" id="sha256">-</value>
            </div>
            
            <div class="card">
                <h3>🛡️ Security Analysis</h3>
                <div id="security-findings"></div>
            </div>
            
            <div class="card">
                <h3>⚙️ System Info</h3>
                <div class="stat">
                    <label>Machine:</label>
                    <value id="machine">-</value>
                </div>
                <div class="stat">
                    <label>Sections:</label>
                    <value id="sections">-</value>
                </div>
                <div class="stat">
                    <label>.NET Assembly:</label>
                    <value id="dotnet">No</value>
                </div>
            </div>
            
            <div class="card full-width">
                <h3>📦 Extracted Resources</h3>
                <div id="resources-info"></div>
            </div>
            
            <div class="card full-width">
                <h3>🔗 Imported APIs</h3>
                <div id="imports-summary"></div>
                <div class="import-list" id="imports-list"></div>
            </div>
            
            <div class="card full-width">
                <h3>📄 String Intelligence</h3>
                <div id="string-intel"></div>
            </div>
        </div>
    </div>
    
    <script>
        async function loadAnalysis() {
            try {
                const response = await fetch('/api/analysis');
                const data = await response.json();
                
                if (data.error) {
                    document.getElementById('dashboard').innerHTML = '<div class="card full-width"><h3>Error</h3><p>' + data.error + '</p></div>';
                    return;
                }
                
                displayAnalysis(data);
            } catch (e) {
                console.error('Failed to load analysis:', e);
            }
        }
        
        function displayAnalysis(data) {
            document.getElementById('filename').textContent = data.basic_info?.filename || '-';
            document.getElementById('filesize').textContent = (data.basic_info?.size || 0).toLocaleString() + ' bytes';
            document.getElementById('md5').textContent = data.basic_info?.md5 || '-';
            document.getElementById('sha256').textContent = data.basic_info?.sha256 || '-';
            document.getElementById('machine').textContent = data.basic_info?.machine || '-';
            document.getElementById('sections').textContent = data.basic_info?.sections || '-';
            document.getElementById('dotnet').textContent = data.basic_info?.is_dotnet ? 'Yes' : 'No';
            
            const secDiv = document.getElementById('security-findings');
            if (data.security?.packed) {
                secDiv.innerHTML = '<div class="security-alert danger">⚠️ Binary appears to be packed</div>';
                secDiv.innerHTML += '<p><strong>Suspicious sections:</strong></p>';
                data.security?.suspicious_sections?.forEach(sec => {
                    secDiv.innerHTML += '<span class="tag danger">' + sec + '</span>';
                });
            } else {
                secDiv.innerHTML = '<div class="security-alert success">✓ No packing detected</div>';
            }
            
            const resDiv = document.getElementById('resources-info');
            const resCount = data.resources?.total || 0;
            resDiv.innerHTML = '<p><strong>' + resCount + '</strong> resources extracted</p>';

            const impsDiv = document.getElementById('imports-summary');
            if (data.imports) {
                const impCount = Object.keys(data.imports).length;
                impsDiv.innerHTML = '<p><strong>' + impCount + '</strong> DLLs imported</p>';
                
                const impList = document.getElementById('imports-list');
                let html = '';
                for (const [dll, apis] of Object.entries(data.imports)) {
                    html += '<div class="import-item"><strong>' + dll + '</strong> (' + apis.length + ' APIs)</div>';
                    apis.slice(0, 3).forEach(api => {
                        html += '<div class="import-item" style="margin-left: 20px; border-left-color: #ccc;">→ ' + api + '</div>';
                    });
                    if (apis.length > 3) {
                        html += '<div class="import-item" style="margin-left: 20px; border-left-color: #ccc; color: #999;">... and ' + (apis.length - 3) + ' more</div>';
                    }
                }
                impList.innerHTML = html;
            }

            const strDiv = document.getElementById('string-intel');
            if (data.strings?.intelligence) {
                const intel = data.strings.intelligence;
                let html = '<p><strong>Extracted Intelligence:</strong></p>';
                if (intel.urls?.length > 0) {
                    html += '<p><strong>URLs found:</strong></p>';
                    intel.urls.slice(0, 5).forEach(url => {
                        html += '<span class="tag warning">' + url + '</span>';
                    });
                }
                if (intel.ips?.length > 0) {
                    html += '<p style="margin-top: 10px;"><strong>IPs found:</strong></p>';
                    intel.ips.slice(0, 5).forEach(ip => {
                        html += '<span class="tag warning">' + ip + '</span>';
                    });
                }
                strDiv.innerHTML = html;
            }
        }
        
        loadAnalysis();
        setInterval(loadAnalysis, 5000);
    </script>
</body>
</html>
"""


@app.route('/')
def dashboard():
    return render_template_string(DASHBOARD_TEMPLATE)


@app.route('/api/analysis')
def get_analysis():
    report_path = request.args.get('report', 'decompiled_output/analysis_report.json')
    
    try:
        with open(report_path, 'r') as f:
            data = json.load(f)
        return jsonify(data)
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/api/files')
def list_files():
    out_dir = request.args.get('dir', 'decompiled_output')
    
    try:
        files = []
        for root, dirs, filenames in os.walk(out_dir):
            for filename in filenames:
                filepath = os.path.join(root, filename)
                files.append({
                    "name": filename,
                    "path": filepath,
                    "size": os.path.getsize(filepath)
                })
        return jsonify({"files": files})
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route('/download/<path:filename>')
def download_file(filename):
    try:
        return send_file(filename, as_attachment=True)
    except Exception as e:
        return str(e), 404


def start_dashboard(port=5000, debug=False):
    """Start the Flask dashboard"""
    print(f"[+] Starting dashboard on http://127.0.0.1:{port}")
    app.run(host='127.0.0.1', port=port, debug=debug)


if __name__ == '__main__':
    start_dashboard(debug=True)