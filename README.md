# Threat Intel Checker

A modern threat intelligence platform that allows users to check files, IP addresses, and URLs against multiple threat intelligence sources. The system provides real-time analysis and detailed reports on potential security threats.

## Features

- **File Analysis**: Check file hashes (MD5, SHA-1, SHA-256) against known malicious files
- **IP Address Checking**: Verify IP addresses against known malicious sources
- **URL Scanning**: Analyze URLs for potential security threats
- **Real-time Results**: Get immediate feedback on threat status
- **Detailed Reports**: View comprehensive analysis including VirusTotal integration
- **Modern UI**: Clean and responsive interface built with Tailwind CSS
- **Database Management**: Add, update, and delete threat entries
- **Activity Logging**: Track all system activities

## Tech Stack

### Backend
- Flask 3.0.2 (Python web framework)
- Flask-SQLAlchemy 3.1.1 (ORM)
- PostgreSQL (Database)
- Flask-CORS 4.0.0 (Cross-Origin Resource Sharing)
- VirusTotal API Integration

### Frontend
- HTML5
- Tailwind CSS (via CDN)
- Vanilla JavaScript
- Responsive Design

## Prerequisites

- Python 3.8+
- PostgreSQL
- VirusTotal API key

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd threat-intel-checker
```

2. Set up the backend:
```bash
cd backend
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements.txt
```

3. Configure environment variables:
Create a `.env` file in the backend directory with the following variables:
```
DATABASE_URL=postgresql://username:password@localhost:5432/threat_intel
VIRUSTOTAL_API_KEY=your_api_key_here
```

4. Initialize the database:
```bash
flask db init
flask db migrate
flask db upgrade
python init_db.py
```

5. Start the backend server:
```bash
flask run
```

6. Serve the frontend:
The frontend is a static HTML file that can be served using any web server. For development, you can use Python's built-in server:
```bash
cd frontend
python -m http.server 8000
```

## Project Structure

```
threat-intel-checker/
├── backend/
│   ├── app.py              # Main Flask application
│   ├── routes.py           # API route definitions
│   ├── models.py           # Database models
│   ├── init_db.py          # Database initialization
│   ├── requirements.txt    # Python dependencies
│   └── .env               # Environment variables
├── frontend               # Single-page frontend application
└── README.md
```

## API Endpoints

### Threat Checking
- GET `/api/check/file` - Check file hash
- GET `/api/check/ip` - Check IP address
- GET `/api/check/url` - Check URL
- POST `/api/check/calculate-hash` - Calculate file hash

### Database Management
- GET `/api/database/stats` - Get database statistics
- GET `/api/database/entries` - Get all database entries
- POST `/api/database/add` - Add new database entry
- DELETE `/api/database/delete/<id>` - Delete database entry
- GET `/api/database/search` - Search database entries

### Activity Logs
- GET `/api/logs` - Get activity logs
- GET `/api/logs/export` - Export activity logs

## Security Considerations

- File uploads are validated and sanitized
- API keys are stored securely in environment variables
- HTTPS is recommended for production deployment
- Implement rate limiting in production
- Add proper input validation
- Set up proper CORS configuration

## Development

To run tests:
```bash
python -m pytest
```

To check code style:
```bash
flake8
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Support

For support, please open an issue in the GitHub repository or contact the maintainers. 