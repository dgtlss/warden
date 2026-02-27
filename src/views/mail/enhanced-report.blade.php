<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>[{{ $appName }}] Warden Security Audit Report</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background-color: #f8fafc;
            margin: 0;
            padding: 40px 20px;
            line-height: 1.6;
            color: #374151;
        }
        .container {
            max-width: 700px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 12px;
            overflow: hidden;
            box-shadow: 0 10px 25px rgba(0,0,0,0.1);
        }
        .header {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        .header .logo {
            margin-bottom: 15px;
        }
        .header .logo img {
            width: 80px;
            height: 80px;
            border-radius: 50%;
            border: 3px solid rgba(255,255,255,0.3);
        }
        .header h1 {
            margin: 0;
            font-size: 28px;
            font-weight: 700;
        }
        .header .subtitle {
            margin: 8px 0 0;
            font-size: 16px;
            opacity: 0.9;
        }
        .content {
            padding: 30px;
        }
        .summary-card {
            background: #f8fafc;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
            border-left: 4px solid #3b82f6;
        }
        .summary-text {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 15px;
        }
        .severity-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(120px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .severity-badge {
            text-align: center;
            padding: 12px;
            border-radius: 8px;
            font-weight: 600;
        }
        .severity-critical { background-color: #fee2e2; color: #dc2626; border: 2px solid #f87171; }
        .severity-high { background-color: #fed7aa; color: #ea580c; border: 2px solid #fb923c; }
        .severity-medium { background-color: #fef3c7; color: #d97706; border: 2px solid #fbbf24; }
        .severity-low { background-color: #d1fae5; color: #059669; border: 2px solid #34d399; }
        
        .findings-section {
            margin-top: 30px;
        }
        .source-group {
            margin-bottom: 30px;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            overflow: hidden;
        }
        .source-header {
            background-color: #f9fafb;
            padding: 15px 20px;
            font-weight: 600;
            font-size: 16px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            color: #374151;
        }
        .finding-item {
            padding: 20px;
            border-bottom: 1px solid #f3f4f6;
        }
        .finding-item:last-child {
            border-bottom: none;
        }
        .finding-header {
            display: flex;
            justify-content: space-between;
            align-items: flex-start;
            margin-bottom: 12px;
        }
        .finding-title {
            font-weight: 600;
            font-size: 16px;
            color: #111827;
            flex: 1;
            margin-right: 15px;
        }
        .finding-severity {
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        .finding-details {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 10px;
            margin-top: 15px;
        }
        .detail-item {
            font-size: 14px;
        }
        .detail-label {
            font-weight: 600;
            color: #6b7280;
            margin-bottom: 2px;
        }
        .detail-value {
            color: #374151;
        }
        .cve-link {
            color: #3b82f6;
            text-decoration: none;
            font-weight: 500;
        }
        .cve-link:hover {
            text-decoration: underline;
        }
        .footer {
            background-color: #f9fafb;
            padding: 20px 30px;
            text-align: center;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #6b7280;
        }
        .footer a {
            color: #3b82f6;
            text-decoration: none;
            font-weight: 500;
        }
        .no-findings {
            text-align: center;
            padding: 40px;
            background-color: #f0fdf4;
            border-radius: 8px;
            margin: 20px 0;
        }
        .no-findings .icon {
            font-size: 48px;
            margin-bottom: 15px;
        }
        .no-findings h3 {
            color: #166534;
            margin: 0 0 10px;
        }
        .no-findings p {
            color: #166534;
            margin: 0;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="https://raw.githubusercontent.com/dgtlss/warden/refs/heads/main/public/warden-logo.png" alt="Warden Logo">
            </div>
            <h1>[{{ $appName }}] Security Audit Report</h1>
            <div class="subtitle">{{ $scanDate->format('F j, Y \a\t g:i A') }}</div>
        </div>

        <div class="content">
            @if($totalFindings > 0)
                <div class="summary-card">
                    <div class="summary-text">{{ $summary }}</div>
                    <div class="severity-grid">
                        <div class="severity-badge severity-critical">
                            <div style="font-size: 20px; margin-bottom: 5px;">{{ $severityCounts['critical'] }}</div>
                            <div>Critical</div>
                        </div>
                        <div class="severity-badge severity-high">
                            <div style="font-size: 20px; margin-bottom: 5px;">{{ $severityCounts['high'] }}</div>
                            <div>High</div>
                        </div>
                        <div class="severity-badge severity-medium">
                            <div style="font-size: 20px; margin-bottom: 5px;">{{ $severityCounts['medium'] }}</div>
                            <div>Medium</div>
                        </div>
                        <div class="severity-badge severity-low">
                            <div style="font-size: 20px; margin-bottom: 5px;">{{ $severityCounts['low'] }}</div>
                            <div>Low</div>
                        </div>
                    </div>
                </div>

                <div class="findings-section">
                    @foreach($findingsBySource as $source => $sourceFindings)
                        <div class="source-group">
                            <div class="source-header">
                                {{ ucfirst($source) }} Audit Results ({{ count($sourceFindings) }} {{ count($sourceFindings) === 1 ? 'issue' : 'issues' }})
                            </div>
                            @foreach($sourceFindings as $finding)
                                <div class="finding-item">
                                    <div class="finding-header">
                                        <div class="finding-title">{{ $finding['title'] }}</div>
                                        <div class="finding-severity severity-{{ $finding['severity'] ?? 'low' }}">
                                            {{ ucfirst($finding['severity'] ?? 'low') }}
                                        </div>
                                    </div>
                                    
                                    <div class="finding-details">
                                        <div class="detail-item">
                                            <div class="detail-label">Package</div>
                                            <div class="detail-value">{{ $finding['package'] ?? 'N/A' }}</div>
                                        </div>
                                        
                                        @if(!empty($finding['cve']) && $finding['cve'] !== '-')
                                        <div class="detail-item">
                                            <div class="detail-label">CVE Reference</div>
                                            <div class="detail-value">
                                                <a href="https://www.cve.org/CVERecord?id={{ $finding['cve'] }}" class="cve-link" target="_blank">
                                                    {{ $finding['cve'] }}
                                                </a>
                                            </div>
                                        </div>
                                        @endif
                                        
                                        @if(!empty($finding['affected_versions']) && $finding['affected_versions'] !== '-')
                                        <div class="detail-item">
                                            <div class="detail-label">Affected Versions</div>
                                            <div class="detail-value">{{ $finding['affected_versions'] }}</div>
                                        </div>
                                        @endif
                                        
                                        @if(!empty($finding['description']))
                                        <div class="detail-item" style="grid-column: 1 / -1;">
                                            <div class="detail-label">Description</div>
                                            <div class="detail-value">{{ $finding['description'] }}</div>
                                        </div>
                                        @endif
                                    </div>
                                </div>
                            @endforeach
                        </div>
                    @endforeach
                </div>
            @else
                <div class="no-findings">
                    <div class="icon">🛡️</div>
                    <h3>All Clear!</h3>
                    <p>No security vulnerabilities detected in this audit.</p>
                </div>
            @endif
        </div>

        <div class="footer">
            <p>This report was automatically generated by <strong>Warden</strong> for <strong>{{ $appName }}</strong></p>
            <p>
                <a href="https://github.com/dgtlss/warden" target="_blank">View on GitHub</a> | 
                <a href="https://packagist.org/packages/dgtlss/warden" target="_blank">Packagist</a>
            </p>
        </div>
    </div>
</body>
</html>