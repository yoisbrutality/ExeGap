#!/usr/bin/env python3
"""
Web Dashboard for EXE Decompiler Analysis Results
Flask-based visualization interface
"""
from flask import Flask, render_template_string, request, send_file, jsonify
import json
import os
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
            font-size: 2.5em;
            color: #667eea;
            margin: 10px 0;
        }
        
        .tag {
            display: inline-block;
            background: #eee;
            padding: 5px 10px;
            border-radius: 20px;
            margin: 5px 5px 0 0;
            font-size: 0.85em;
            color: #666;
        }
        
        .success { background: #e6ffe6; color: #388e3c; }
        .warning { background: #fff4e6; color: #f57c00; }
        .danger { background: #ffe6e6; color: #d32f2f; }
        
        #upload-section {
            background: white;
            border-radius: 10px;
            padding: 30px;
            margin-bottom: 30px;
            box-shadow: 0 10px 30px rgba(0, 0, 0, 0.1);
            text-align: center;
        }
        
        #file-input {
            display: none;
        }
        
        .upload-btn {
            background: #667eea;
            color: white;
            padding: 12px 25px;
            border-radius: 5px;
            cursor: pointer;
            font-weight: bold;
            transition: background 0.3s;
        }
        
        .upload-btn:hover {
            background: #764ba2;
        }
        
        #progress {
            margin-top: 20px;
            height: 5px;
            background: #eee;
            border-radius: 5px;
            overflow: hidden;
        }
        
        #progress-bar {
            height: 100%;
            width: 0;
            background: #667eea;
            transition: width 0.3s;
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 EXE Decompiler Dashboard</h1>
            <p class="subtitle">Professional binary analysis & visualization suite</p>
        </header>
        
        <div id="upload-section">
            <label for="file-input" class="upload-btn">📤 Upload Binary for Analysis</label>
            <input type="file" id="file-input" accept=".exe,.dll">
            <div id="progress"><div id="progress-bar"></div></div>
        </div>
        
        <div class="dashboard" id="dashboard"></div>
    </div>
    
    <script>
        const fileInput = document.getElementById('file-input');
        const progressBar = document.getElementById('progress-bar');
        const dashboard = document.getElementById('dashboard');
        
        fileInput.addEventListener('change', async (e) => {
            const file = e.target.files[0];
            if (!file) return;
            
            const formData = new FormData();
            formData.append('file', file);
            
            try {
                progressBar.style.width = '20%';
                
                const response = await fetch('/api/analyze', {
                    method: 'POST',
                    body: formData
                });
                
                progressBar.style.width = '60%';
                
                if (!response.ok) {
                    throw new Error('Analysis failed');
                }
                
                const data = await response.json();
                progressBar.style.width = '100%';
                renderDashboard(data);
            } catch (error) {
                alert('Error: ' + error.message);
            } finally {
                setTimeout(() => progressBar.style.width = '0%', 1000);
            }
        });
        
        function renderDashboard(data) {
            dashboard.innerHTML = '';
            
            // Metadata Card
            const metaCard = document.createElement('div');
            metaCard.className = 'card';
            metaCard.innerHTML = `
                <h3>📋 Binary Metadata</h3>
                <p><strong>File:</strong> ${data.file || 'Unknown'}</p>
                <p><strong>Size:</strong> ${(data.size / 1024).toFixed(2)} KB</p>
                <p><strong>MD5:</strong> ${data.md5 || 'N/A'}</p>
            `;
            dashboard.appendChild(metaCard);
            
            // Security Card
            const secCard = document.createElement('div');
            secCard.className = 'card';
            const packed = data.security?.packed ? 'danger' : 'success';
            secCard.innerHTML = `
                <h3>🛡️ Security Analysis</h3>
                <span class="tag ${packed}">Packed: ${data.security?.packed ? 'Yes' : 'No'}</span>
                <p><strong>Risk Level:</strong> ${data.security?.risk_level || 'Low'}</p>
            `;
            dashboard.appendChild(secCard);
        }
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
