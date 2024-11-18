<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <meta http-equiv="X-UA-Compatible" content="ie=edge">
    <title>Warden Audit Report</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            background-color: #f5f5f5;
            margin: 0;
            padding: 40px 20px;
        }
        .container {
            max-width: 600px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 8px;
            padding: 30px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .logo {
            text-align: center;
            margin-bottom: 20px;
        }
        .logo img {
            max-width: 200px;
            height: auto;
        }
        .title {
            font-size: 24px;
            font-weight: bold;
            color: #333333;
            text-align: center;
            margin-bottom: 30px;
        }
        .report-content {
            color: #444444;
            line-height: 1.6;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            margin: 20px 0;
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #eeeeee;
        }
        th {
            background-color: #f8f8f8;
            font-weight: 600;
        }
        footer{
            display: flex;
            justify-content: center;
            align-items: center;
            margin-top: 30px;
            flex-direction: column;
            gap: 2px;
            font-size: 12px;
        }
        footer a {
            color: #333333;
            text-decoration: none;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="logo">
            <img src="https://github.com/dgtlss/warden/blob/main/public/warden-logo.png" alt="Logo">
        </div>
        <div class="title">
            Warden Audit Report
        </div>
        <div class="report-content">
            <p>Here is your warden audit report for {{ now()->format('F j, Y') }}.</p>

            @foreach($report as $package => $issues)
                <h2>Package: {{ $package }}</h2>
                <ul>
                    @foreach($issues as $issue)
                        <li>Title: {{ $issue['title'] }}</li>
                        <li>CVE: {{ $issue['cve'] }}</li>
                        <li>Link: <a href="{{ $issue['link'] }}" target="_blank">{{ $issue['link'] }}</a></li>
                        <li>Affected Versions: {{ $issue['affected_versions'] }}</li>
                    @endforeach
                </ul>
            @endforeach

            <footer>
                <span>This report was automatically generated by Warden.</span>
                <a href="https://github.com/dgtlss/warden">Warden on GitHub</a>
            </footer>
        </div>
    </div>
</body>
</html>