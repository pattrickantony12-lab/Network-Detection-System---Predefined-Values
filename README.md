🚀 Network Intrusion Detection System (NIDS)
A real-time Network Intrusion Detection System (NIDS) built using Flask that monitors network traffic, detects cyber threats, and provides live visualization along with automated forensic reporting.
________________________________________
📌 Overview
This project simulates and analyzes network packets to identify malicious activities such as DDoS attacks, XSS injections, brute force attempts, and exploits. It features a modern dashboard for live monitoring and generates detailed PDF reports for security analysis.
________________________________________
✨ Features
•	🔍 Real-time packet monitoring and analysis

•	⚠️ Detection of multiple attack types

•	📊 Interactive dashboard with live charts (Chart.js)

•	📡 Real-time updates using Socket.IO

•	🗄️ Database storage using SQLAlchemy

•	📄 Automated forensic PDF report generation

•	🔐 User authentication (Login/Register system)
________________________________________
🛠️ Tech Stack
•	Backend: Flask (Python)
•	Frontend: HTML, CSS, JavaScript
•	Database: SQLite (SQLAlchemy ORM)
•	Visualization: Chart.js, Matplotlib
•	Real-time Communication: Socket.IO
•	Reporting: ReportLab
________________________________________
⚙️ Installation & Setup
1. Clone the Repository
git clone 
cd nids-project
2. Create Virtual Environment
python -m venv venv
source venv/bin/activate   # For Linux/Mac
venv\Scripts\activate      # For Windows
3. Install Dependencies
pip install -r requirements.txt
4. Run the Application
python app.py
5. Open in Browser

________________________________________
🧠 How It Works
1.	Network packets are simulated or captured.
2.	The system analyzes packet data and classifies it as normal or malicious.
3.	Attack type, severity, and confidence level are assigned.
4.	Data is stored in the database and displayed on a live dashboard.
5.	Users can generate detailed forensic reports in PDF format.
________________________________________
📊 Dashboard Features
•	Live packet monitoring table
•	Threat detection status indicator
•	Attack distribution (Pie Chart)
•	Network activity over time (Bar Chart)
________________________________________
📄 Report Generation
•	Generates professional forensic reports in PDF format
•	Includes:
o	Attack distribution chart
o	Protocol analysis chart
o	Detailed log table with severity levels
________________________________________
🔐 Authentication
•	Secure user registration and login system
•	Password hashing using Werkzeug security
________________________________________
🧪 Testing
•	Manual testing for system functionality
•	Chrome DevTools (Elements, Console, Network)
•	Backend debugging using Flask logs
•	Database validation using SQLAlchemy
________________________________________
🔮 Future Enhancements
•	Integration with real network traffic
•	Machine learning-based threat detection
•	Cloud deployment
•	Email/SMS alert system
________________________________________
🎯 Objective
To provide a real-time, efficient, and user-friendly solution for detecting and analyzing network intrusions with visualization and reporting capabilities.
________________________________________
📸 Screenshots
Add your project screenshots here
________________________________________
📜 License
This project is open-source and available under the MIT License.
________________________________________
🙌 Author
Your Name
________________________________________
⭐ If you like this project, consider giving it a star!
