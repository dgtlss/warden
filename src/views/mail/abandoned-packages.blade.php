<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>[{{ $appName }}] Warden Abandoned Packages Report</title>
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
            background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%);
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
            background: #fffbeb;
            border: 1px solid #fbbf24;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 30px;
        }
        .summary-text {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 15px;
            color: #92400e;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 15px;
            margin-top: 15px;
        }
        .stat-item {
            text-align: center;
            padding: 15px;
            background: white;
            border-radius: 8px;
            border: 1px solid #fbbf24;
        }
        .stat-number {
            font-size: 24px;
            font-weight: 700;
            color: #d97706;
            margin-bottom: 5px;
        }
        .stat-label {
            font-size: 14px;
            color: #92400e;
        }
        .packages-list {
            margin-top: 30px;
        }
        .package-item {
            background: #fafafa;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 15px;
        }
        .package-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }
        .package-name {
            font-weight: 600;
            font-size: 16px;
            color: #111827;
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            background: #f3f4f6;
            padding: 4px 8px;
            border-radius: 4px;
        }
        .package-status {
            background: #fbbf24;
            color: white;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
            text-transform: uppercase;
        }
        .replacement-info {
            background: #f0fdf4;
            border: 1px solid #bbf7d0;
            border-radius: 6px;
            padding: 12px;
            margin-top: 10px;
        }
        .replacement-label {
            font-size: 12px;
            font-weight: 600;
            color: #166534;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 5px;
        }
        .replacement-package {
            font-family: 'Monaco', 'Menlo', 'Ubuntu Mono', monospace;
            font-weight: 600;
            color: #15803d;
        }
        .no-replacement {
            color: #6b7280;
            font-style: italic;
            font-size: 14px;
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
        .info-box {
            background: #eff6ff;
            border: 1px solid #93c5fd;
            border-radius: 8px;
            padding: 15px;
            margin: 20px 0;
        }
        .info-title {
            font-weight: 600;
            color: #1d4ed8;
            margin-bottom: 8px;
        }
        .info-text {
            color: #1e40af;
            font-size: 14px;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="logo">
                <img src="https://raw.githubusercontent.com/dgtlss/warden/refs/heads/main/public/warden-logo.png" alt="Warden Logo">
            </div>
            <h1>[{{ $appName }}] Abandoned Packages Alert</h1>
            <div class="subtitle">{{ $scanDate->format('F j, Y \a\t g:i A') }}</div>
        </div>

        <div class="content">
            <div class="summary-card">
                <div class="summary-text">
                    ⚠️ {{ $totalPackages }} abandoned {{ $totalPackages === 1 ? 'package' : 'packages' }} detected in your dependencies
                </div>
                <div class="stats-grid">
                    <div class="stat-item">
                        <div class="stat-number">{{ $totalPackages }}</div>
                        <div class="stat-label">Total Abandoned</div>
                    </div>
                    <div class="stat-item">
                        <div class="stat-number">{{ count($packagesWithReplacements) }}</div>
                        <div class="stat-label">With Replacements</div>
                    </div>
                </div>
            </div>

            <div class="info-box">
                <div class="info-title">What are abandoned packages?</div>
                <div class="info-text">
                    Abandoned packages are no longer maintained by their authors and may pose security risks over time. 
                    Consider migrating to recommended alternatives or actively maintained forks.
                </div>
            </div>

            <div class="packages-list">
                <h3 style="color: #374151; margin-bottom: 20px;">Package Details</h3>
                
                @foreach($abandonedPackages as $package)
                    <div class="package-item">
                        <div class="package-header">
                            <div class="package-name">{{ $package['package'] }}</div>
                            <div class="package-status">Abandoned</div>
                        </div>
                        
                        @if(!empty($package['replacement']))
                            <div class="replacement-info">
                                <div class="replacement-label">Recommended Replacement</div>
                                <div class="replacement-package">{{ $package['replacement'] }}</div>
                            </div>
                        @else
                            <div class="no-replacement">No replacement package suggested</div>
                        @endif
                    </div>
                @endforeach
            </div>

            <div class="info-box">
                <div class="info-title">Recommended Actions</div>
                <div class="info-text">
                    1. Review each abandoned package and assess its usage in your application<br>
                    2. For packages with replacements, plan migration to the suggested alternatives<br>
                    3. For packages without replacements, research actively maintained forks or alternatives<br>
                    4. Update your composer.json to remove or replace abandoned dependencies
                </div>
            </div>
        </div>

        <div class="footer">
            <p>This report was automatically generated by <strong>Warden v1.3.5</strong> for <strong>{{ $appName }}</strong></p>
            <p>
                <a href="https://github.com/dgtlss/warden" target="_blank">View on GitHub</a> | 
                <a href="https://packagist.org/packages/dgtlss/warden" target="_blank">Packagist</a>
            </p>
        </div>
    </div>
</body>
</html>